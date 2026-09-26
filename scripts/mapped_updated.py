#!/usr/bin/env python3
# mapper.py
#
# Purpose:
#   Map fully-qualified Java methods (e.g., `java.lang.System.nanoTime`) to their
#   native implementations by combining several sources of truth:
#     1) Exported symbols in ELF libraries (via nm) for standard JNI `Java_*` methods.
#     2) RegisterNatives tables extracted directly from the container's libjvm.so
#        binary (via extract_registernatives_binary.py), linking Java methods to
#        C targets (e.g., `JVM_*` or custom functions).  Falls back to OpenJDK
#        source `JNINativeMethod` tables (when `JVM_SRC` is set).
#     3) Symbol resolution across transitive runtime dependencies (via ldd) to
#        identify which `.so` actually defines a target symbol.
#     4) jni_dynamic_bindings.txt from OUTPUTS_DIR/<IMG_NAME>/ ONLY
#        (the canonical extract_jni_bindings.py output for this container);
#        plus optional JNI_DYNAMIC_BINDING_DIRS (explicit opt-in via env var).
#        cwd / LIBS_<IMG_NAME>/ / supplemental third-party dirs (netty_libs,
#        netty_libs_all, hawtjni_libs, hadoop_libs, hadoop_ec_downloads) are
#        no longer auto-walked: those generic dumps cover Netty/Hadoop versions
#        the container does not actually ship and leaked false positives.
#
# Key environment inputs:
#   - LIB_DIRS: os.pathsep-separated directories to scan for ELF `.so` files.
#     Under each LIBS_<IMG_NAME> directory, optional subfolders named JDK<N>_LIBS/
#     (e.g. JDK11_LIBS/) are auto-discovered.  Also supported:
#       - JDK_LIBS_DIRS / JDK_LIBS_DIR: explicit path(s) to JDK<N>_LIBS trees
#         (pathsep-separated, same as LIB_DIRS).
#       - Sibling fallback: if LIBS_<name>-slim has no JDK*_LIBS/, also look under
#         LIBS_<name>/ (strip trailing "-slim") for JDK*_LIBS/.
#   - JVM_SRC:  Path to the OpenJDK source tree (optional).
#   - JVM_SO:   Explicit path to `libjvm.so` (optional, auto-discovered if unset).
#   - METHODS_FILE: File listing Java methods (one per line) to classify.
#   - OUTPUTS_DIR: Directory for output files (default: current directory).
#   - JNI_DYNAMIC_BINDING_DIRS (optional): extra directories that contain
#     jni_dynamic_bindings.txt (same path separator as LIB_DIRS).
#
# Outputs (in OUTPUTS_DIR):
#   - mapped_method_syscalls.txt: Per-method resolution details and classification tags.

import os
import re
import sys
import glob
import subprocess
import json
import time

# ----------------------------
# Config / Inputs
# ----------------------------
# Project root is the repository root, even when this helper lives under scripts/.
# Used to render LIBS_<IMG_NAME>/libfoo.so as a project-relative path in the output.
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR) if os.path.basename(SCRIPT_DIR) == "scripts" else SCRIPT_DIR

env_lib_dirs = os.environ.get("LIB_DIRS")
if env_lib_dirs:
    LIB_DIRS = [p for p in env_lib_dirs.split(os.pathsep) if p]
else:
    lib_base = os.environ.get("LIBS_IMAGE") or os.environ.get("LIBS_DIR")
    if lib_base:
        LIB_DIRS = [lib_base]
    else:
        sys.stderr.write(
            "ERROR: No library directories configured.\n"
            "Please set one of the following environment variables:\n"
            "  - LIB_DIRS: colon-separated list of directories to scan for .so files\n"
            "  - LIBS_IMAGE: single directory containing libraries for a specific container image\n"
            "  - LIBS_DIR: single directory containing libraries\n"
            "Optional — container JDK native libs (libjava.so, server/libjvm.so, …):\n"
            "  - Put them under LIBS_<IMG>/JDK<N>_LIBS/ (see scripts/extract_container_jdk.py --libs-only), or\n"
            "  - Set JDK_LIBS_DIRS (or JDK_LIBS_DIR) to explicit JDK<N>_LIBS path(s).\n"
        )
        sys.exit(1)

if not LIB_DIRS:
    sys.stderr.write("ERROR: LIB_DIRS is empty after configuration.\n")
    sys.exit(1)


def normalize_lib_dirs(lib_dirs: list) -> list:
    """
    Normalize known LIB_DIRS path variants.
    If a configured path does not exist and there is a sibling Extracted_Data/LIBS_* path,
    use the existing Extracted_Data path automatically.
    """
    normalized = []
    for lib_dir in lib_dirs:
        if os.path.isdir(lib_dir):
            normalized.append(lib_dir)
            continue
        alt = os.path.join(os.path.dirname(lib_dir), "Extracted_Data", os.path.basename(lib_dir))
        if os.path.isdir(alt):
            normalized.append(alt)
        else:
            normalized.append(lib_dir)
    return normalized

JVM_SRC = os.environ.get("JVM_SRC",
                         os.path.join(PROJECT_ROOT, ".tmp_jdk8_native/jdk/src/share/native"))
JVM_SRC_NORM = os.path.expanduser((JVM_SRC or "").strip().strip('"').strip("'"))
JVM_SO  = os.environ.get("JVM_SO", "")
output_dir = os.environ.get("OUTPUTS_DIR", ".").strip() or "."

DEBUG_LOG_PATH = os.path.join(PROJECT_ROOT, ".cursor", "debug-2d3c38.log")
DEBUG_SESSION_ID = "2d3c38"


def debug_log(run_id: str, hypothesis_id: str, message: str, data: dict):
    payload = {
        "sessionId": DEBUG_SESSION_ID,
        "runId": run_id,
        "hypothesisId": hypothesis_id,
        "location": "mapped_updated.py",
        "message": message,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }
    try:
        with open(DEBUG_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(payload, ensure_ascii=True) + "\n")
    except Exception:
        pass

# #region agent log
debug_log("mapper-bootstrap", "H0", "mapped_updated.py module loaded", {
    "pythonExecutable": sys.executable,
    "cwd": os.getcwd(),
})
# #endregion

LIB_DIRS = normalize_lib_dirs(LIB_DIRS)

# Auto-append LIBS_<IMG>/JDK<N>_LIBS/, explicit JDK_LIBS_DIRS, and -slim sibling fallback.
_JDK_LIBS_SUBDIR = re.compile(r"^JDK\d+_LIBS$")


def _explicit_jdk_libs_dirs_from_env():
    raw = os.environ.get("JDK_LIBS_DIRS") or os.environ.get("JDK_LIBS_DIR") or ""
    out = []
    for p in raw.split(os.pathsep):
        p = p.strip()
        if not p:
            continue
        if os.path.isdir(p):
            out.append(os.path.abspath(p))
        else:
            print(f"WARN: JDK_LIBS path does not exist (skipped): {p}", file=sys.stderr)
    return out


def collect_jdk_native_tree_dirs(seed_lib_dirs: list) -> list:
    """
    Find JDK<N>_LIBS directories to scan for libjava.so / server/libjvm.so, etc.

    Sources (de-duplicated):
      1) JDK_LIBS_DIRS / JDK_LIBS_DIR env
      2) Direct children JDK<N>_LIBS under each entry in seed_lib_dirs
      3) If dir basename ends with '-slim', same under sibling LIBS_<rest>/JDK<N>_LIBS/

    Returns list of (abs_path, source_label).
    """
    entries = []  # (abs_path, label)
    seen = set()

    def add(path: str, label: str):
        a = os.path.abspath(path)
        if a not in seen and os.path.isdir(a):
            seen.add(a)
            entries.append((a, label))

    for a in _explicit_jdk_libs_dirs_from_env():
        add(a, f"env: {a}")

    for d in seed_lib_dirs:
        abs_d = os.path.abspath(d)
        if not os.path.isdir(abs_d):
            continue
        try:
            names = sorted(os.listdir(abs_d))
        except OSError:
            names = []
        for name in names:
            if not _JDK_LIBS_SUBDIR.match(name):
                continue
            sub = os.path.join(abs_d, name)
            if os.path.isdir(sub):
                add(sub, f"child: {abs_d}/{name}")

        base = os.path.basename(abs_d)
        parent = os.path.dirname(abs_d)
        if base.endswith("-slim"):
            sibling = os.path.join(parent, base[:-5])
            if os.path.isdir(sibling):
                try:
                    s_names = sorted(os.listdir(sibling))
                except OSError:
                    s_names = []
                for name in s_names:
                    if not _JDK_LIBS_SUBDIR.match(name):
                        continue
                    sub = os.path.join(sibling, name)
                    if os.path.isdir(sub):
                        add(sub, f"sibling: {sibling}/{name} (for {base})")

    return entries


def merge_lib_dirs_with_jdk_trees(user_lib_dirs: list, tuples_jdk: list):
    """Prefix order: user roots first, then JDK trees. tuples_jdk: [(path, label), ...].
    Returns (merged_abs_paths, list of (added_path, label) for logging)."""
    jdk_paths = [p for p, _ in tuples_jdk]
    label_for = {os.path.abspath(p): lb for p, lb in tuples_jdk}
    seen = set()
    merged = []
    for d in user_lib_dirs:
        a = os.path.abspath(d)
        if a not in seen:
            seen.add(a)
            merged.append(a)
    added_pairs = []
    for a in jdk_paths:
        a = os.path.abspath(a)
        if a not in seen:
            merged.append(a)
            seen.add(a)
            added_pairs.append((a, label_for.get(a, "")))
    return merged, added_pairs


_user_lib_abs = [os.path.abspath(d) for d in LIB_DIRS]
_jdk_entries = collect_jdk_native_tree_dirs(_user_lib_abs)
LIB_DIRS, _jdk_added_pairs = merge_lib_dirs_with_jdk_trees(_user_lib_abs, _jdk_entries)
_JDK_NATIVE_EXTRA = [p for p, _ in _jdk_added_pairs]
if _JDK_NATIVE_EXTRA:
    print("INFO: Appended JDK native lib trees (JDK*_LIBS/) for symbol scan:")
    for p, lab in _jdk_added_pairs:
        print(f"  + {p}")
        print(f"      ({lab})")

# The script is strictly per-container: only the user-provided LIBS_<IMG_NAME>
# directories feed symbol/binding resolution.  Supplemental third-party native
# bundles (the previous netty_libs / netty_libs_all / hawtjni_libs / hadoop_libs
# / hadoop_ec_downloads list) and JDK-specific fallbacks (system
# /usr/lib/jvm/java-8-openjdk-amd64/*, LIBS_jdk8_temurin) have all been removed
# deliberately:
#   * extract_jni_bindings.py now ships per-container output at
#     OUTPUTS_DIR/<IMG_NAME>/jni_dynamic_bindings.txt for the Netty/HawtJNI/
#     Hadoop/etc. bundles the container actually loads.
#   * extract_registernatives_binary.py on LIBS_<IMG_NAME>/libjvm.so covers
#     JVM_*/Unsafe_*/MHN_* etc., filtered against libjvm.so symbols.
# Mixing in generic third-party dumps was leaking versions of Netty/Hadoop/SWT
# the container does not ship; mixing in JDK-8 system libs produced false
# positives like
#   libnio.so:java.nio.MappedByteBuffer.force0 -> Java_java_nio_MappedByteBuffer_force0
# against a JDK-17 container that actually exports Java_java_nio_MappedMemoryUtils_force0.
PRIMARY_LIB_DIRS = list(LIB_DIRS)


# Resolve a library path to a priority bucket. Lower number = higher priority.
# 0..len(PRIMARY_LIB_DIRS)-1: inside a user-provided LIB_DIR (LIBS_<IMG_NAME>)
# 999:                         anywhere else (system path / ldd-resolved / unknown)
_PRIMARY_LIB_DIRS_ABS = [os.path.abspath(d) for d in PRIMARY_LIB_DIRS]


def lib_priority(lib_path):
    if not lib_path:
        return 999
    abs_path = os.path.abspath(lib_path)
    for i, ad in enumerate(_PRIMARY_LIB_DIRS_ABS):
        if abs_path == ad or abs_path.startswith(ad + os.sep):
            return i
    return 999

print("DEBUG: Using LIB_DIRS:")
for d in LIB_DIRS:
    print("  -", d)


def resolve_methods_file():
    env_methods = os.environ.get("METHODS_FILE")
    if env_methods:
        return env_methods
    if output_dir not in (".", ""):
        return os.path.join(output_dir, "native_methods.txt")
    return "native_methods.txt"


def ensure_methods_file(path: str):
    if os.path.exists(path):
        return
    sys.stderr.write(
        f"ERROR: Methods file not found: {path}\n"
        "Set METHODS_FILE or OUTPUTS_DIR to point to an existing native_methods.txt.\n"
    )
    sys.exit(1)


methods_file = resolve_methods_file()
ensure_methods_file(methods_file)


def load_methods(path: str) -> list:
    with open(path, "r", encoding="utf-8") as f:
        methods = []
        for line in f:
            line = line.strip()
            if not line:
                continue
            # Skip malformed entries from previous analysis runs (output classifications that got into input)
            if line in ("NOT_FOUND_IN_LIBS", "PLATFORM_EXCLUDED"):
                continue
            if line.startswith("NATIVE_METHOD_NOT_IN_THIS_BUILD"):
                continue
            if line.startswith("PLATFORM_EXCLUDED ("):
                continue
            methods.append(line)
        return methods


def discover_shaded_netty_prefixes(methods: list) -> list:
    """
    Find relocated Netty package roots (e.g. com.datastax.shaded.netty).
    Same JNI natives Register as io.netty.*; JNI_DYNAMIC tables use canonical io.netty FQNs.
    """
    prefixes = set()
    netty_pkg_rx = re.compile(
        r"^([a-zA-Z][a-zA-Z0-9_$.]*\.netty)\.(channel\.(unix|epoll|kqueue)|internal\.tcnative)\."
    )
    try:
        for line in methods:
            m = netty_pkg_rx.match(line)
            if m:
                prefix = m.group(1)
                if prefix != "io.netty":
                    prefixes.add(prefix)
    except Exception as e:
        print(f"WARN: Could not discover shaded netty prefixes: {e}", file=sys.stderr)

    result = sorted(prefixes)
    if result:
        print(f"INFO: Shaded Netty prefixes (JNI_DYNAMIC alias): {result}")
    return result


def iter_jni_dynamic_lookup_keys(original: str, lookup: str, shaded_prefixes: list):
    """Yield candidates for jni_dynamic_map: bytecode FQN, lookup, shaded→io.netty,
    and Errors ↔ ErrorsStaticallyReferencedJniMethods (extractor historically used Errors.*)."""
    declared = "io.netty.channel.unix.ErrorsStaticallyReferencedJniMethods."
    inferred_bad = "io.netty.channel.unix.Errors."

    seeds = []
    for m in (original, lookup):
        if not m:
            continue
        seeds.append(m)
        for p in shaded_prefixes:
            if m.startswith(p + "."):
                seeds.append(m.replace(p, "io.netty", 1))

    expanded = []
    for m in seeds:
        expanded.append(m)
        if m.startswith(declared):
            expanded.append(inferred_bad + m[len(declared):])
        elif m.startswith(inferred_bad):
            expanded.append(declared + m[len(inferred_bad):])

    seen = set()
    for m in expanded:
        if m not in seen:
            seen.add(m)
            yield m


# Methods on io.netty.channel.unix.Socket whose JNI signatures are built dynamically at JNI_OnLoad
# (see netty_unix_socket.c: recvFromAddress / recvFromDomainSocket). Static jni_dynamic_bindings
# extraction misses them; exported symbols follow netty_unix_socket_<jniSimpleName>.
_NETTY_UNIX_SOCKET_MARKER = ".channel.unix.Socket."
_NETTY_UNIX_SOCKET_JNI_SIMPLE_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")


def try_netty_unix_socket_nm_fallback(original: str, lookup: str, shaded_prefixes: list, libs: list):
    """
    Resolve RegisterNatives-backed unix.Socket methods via exported netty_unix_socket_* symbols.
    """
    for m in iter_jni_dynamic_lookup_keys(original, lookup, shaded_prefixes):
        idx = m.find(_NETTY_UNIX_SOCKET_MARKER)
        if idx < 0:
            continue
        jni_simple = m[idx + len(_NETTY_UNIX_SOCKET_MARKER):]
        if not jni_simple or not _NETTY_UNIX_SOCKET_JNI_SIMPLE_RE.match(jni_simple):
            continue
        sym = f"netty_unix_socket_{jni_simple}"
        owner = resolve_symbol_in_libs(sym, libs)
        if owner:
            return owner, sym, m
    return None


_NETTY_JAVA_MEMBER_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$]*$")


def netty_epoll_java_class_token(java_simple_class: str) -> str:
    """LinuxSocket -> linuxsocket (matches netty_epoll_* native prefixes)."""
    parts = re.findall(r"[A-Z][a-z]*|[a-z]+|[0-9]+", java_simple_class)
    return "".join(p.lower() for p in parts)


def try_netty_internal_tcnative_nm_fallback(original: str, lookup: str, shaded_prefixes: list, libs: list):
    """
    netty_internal_tcnative_SSLContext_addFoo -> io.netty.internal.tcnative.SSLContext.addFoo
    Used when JNI_DYNAMIC misses (new methods, odd layouts). Class name keeps Java PascalCase in the symbol.
    """
    marker = ".internal.tcnative."
    for m in iter_jni_dynamic_lookup_keys(original, lookup, shaded_prefixes):
        pos = m.find(marker)
        if pos < 0:
            continue
        tail = m[pos + len(marker):]
        dot = tail.rfind(".")
        if dot <= 0:
            continue
        cls, meth = tail[:dot], tail[dot + 1:]
        if not _NETTY_JAVA_MEMBER_RE.match(cls) or not _NETTY_JAVA_MEMBER_RE.match(meth):
            continue
        sym = f"netty_internal_tcnative_{cls}_{meth}"
        owner = resolve_symbol_in_libs(sym, libs)
        if owner:
            return owner, sym, m
    return None


def try_netty_channel_epoll_nm_fallback(original: str, lookup: str, shaded_prefixes: list, libs: list):
    """
    netty_epoll_linuxsocket_getPeerCredentials -> io.netty.channel.epoll.LinuxSocket.getPeerCredentials
    Same idea as unix.Socket nm fallback: symbols always exported even when ELF RegisterNatives extraction misses.
    """
    marker = ".channel.epoll."
    for m in iter_jni_dynamic_lookup_keys(original, lookup, shaded_prefixes):
        pos = m.find(marker)
        if pos < 0:
            continue
        tail = m[pos + len(marker):]
        dot = tail.rfind(".")
        if dot <= 0:
            continue
        cls, meth = tail[:dot], tail[dot + 1:]
        if not _NETTY_JAVA_MEMBER_RE.match(cls) or not _NETTY_JAVA_MEMBER_RE.match(meth):
            continue
        tok = netty_epoll_java_class_token(cls)
        sym = f"netty_epoll_{tok}_{meth}"
        owner = resolve_symbol_in_libs(sym, libs)
        if owner:
            return owner, sym, m
    return None


methods = load_methods(methods_file)
shaded_netty_prefixes = discover_shaded_netty_prefixes(methods)

detailed_output_file = os.path.join(output_dir, "mapped_method_syscalls.txt")


def load_intrinsic_whitelist() -> set:
    """
    Load the JVM intrinsic whitelist — methods inlined by the JIT compiler
    that have no corresponding symbol in any .so file.
    Searches: INTRINSICS_FILE env var, then OUTPUTS_DIR, then cwd.
    """
    candidates = []
    env_path = os.environ.get("INTRINSICS_FILE")
    if env_path:
        candidates.append(env_path)
    if output_dir not in (".", ""):
        candidates.append(os.path.join(output_dir, "intrinsic_whitelist_all_jdks.txt"))
    candidates.append("intrinsic_whitelist_all_jdks.txt")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    # Bounded fallbacks to avoid expensive recursive directory traversal.
    candidates.append(os.path.join(script_dir, "intrinsic_whitelist_all_jdks.txt"))
    candidates.extend(
        glob.glob(os.path.join(script_dir, "outputs_*", "intrinsic_whitelist_all_jdks.txt"))
    )

    seen = set()
    ordered_candidates = []
    for path in candidates:
        if path and path not in seen:
            ordered_candidates.append(path)
            seen.add(path)

    for path in ordered_candidates:
        if os.path.isfile(path):
            entries = set()
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        entries.add(line)
            print(f"INFO: Loaded {len(entries)} intrinsic methods from {path}")
            return entries

    print("INFO: No intrinsic whitelist found (optional). Skipping intrinsic classification.")
    return set()


intrinsic_methods = load_intrinsic_whitelist()

# ----------------------------
# JVM built-in native mappings
# ----------------------------
# Methods resolved by the JVM's internal NativeLookup rather than through
# JNI symbol export or JNINativeMethod registration tables.
# These are well-known in the JVM spec and unlikely to change.
JVM_BUILTIN_NATIVES = {
    "java.lang.Object.wait":            "JVM_MonitorWait",
    "java.lang.Object.notify":          "JVM_MonitorNotify",
    "java.lang.Object.notifyAll":       "JVM_MonitorNotifyAll",
    "java.lang.Object.hashCode":        "JVM_IHashCode",
    "java.lang.Object.clone":           "JVM_Clone",
    # System methods registered in libjava.so's JNI_OnLoad but targeting libjvm.so exports
    "java.lang.System.arraycopy":       "JVM_ArrayCopy",
    "java.lang.System.currentTimeMillis": "JVM_CurrentTimeMillis",
    "java.lang.System.nanoTime":        "JVM_NanoTime",
}

# Some Unsafe natives exist as local (non-exported) libjvm symbols and are not
# present in our current intrinsic/registered source tables for a given JDK build.
UNSAFE_LOCAL_FALLBACKS = {
    "jdk.internal.misc.Unsafe.allocateMemory0": "Unsafe_AllocateMemory0",
    "jdk.internal.misc.Unsafe.objectFieldOffset0": "Unsafe_ObjectFieldOffset0",
    "jdk.internal.misc.Unsafe.shouldBeInitialized0": "Unsafe_ShouldBeInitialized0",
}

# ----------------------------
# Unsafe legacy name aliases  (JDK <14 names → JDK 17+ names)
# ----------------------------
# Methods renamed in JDK 14 (JDK-8220793): Object→Reference.
# Bytecode compiled against older JDKs still references the old names.
# Map old name → new name so the source-scan and intrinsic lookups succeed.
UNSAFE_RENAMED = {
    "jdk.internal.misc.Unsafe.compareAndSetObject":      "jdk.internal.misc.Unsafe.compareAndSetReference",
    "jdk.internal.misc.Unsafe.compareAndExchangeObject":  "jdk.internal.misc.Unsafe.compareAndExchangeReference",
    "jdk.internal.misc.Unsafe.getObject":                "jdk.internal.misc.Unsafe.getReference",
    "jdk.internal.misc.Unsafe.putObject":                "jdk.internal.misc.Unsafe.putReference",
    "jdk.internal.misc.Unsafe.getObjectVolatile":        "jdk.internal.misc.Unsafe.getReferenceVolatile",
    "jdk.internal.misc.Unsafe.putObjectVolatile":        "jdk.internal.misc.Unsafe.putReferenceVolatile",
    "jdk.internal.misc.Unsafe.getObjectOpaque":          "jdk.internal.misc.Unsafe.getReferenceOpaque",
    "jdk.internal.misc.Unsafe.putObjectOpaque":          "jdk.internal.misc.Unsafe.putReferenceOpaque",
    "jdk.internal.misc.Unsafe.getObjectAcquire":         "jdk.internal.misc.Unsafe.getReferenceAcquire",
    "jdk.internal.misc.Unsafe.putObjectRelease":         "jdk.internal.misc.Unsafe.putReferenceRelease",
    "jdk.internal.misc.Unsafe.getAndSetObject":          "jdk.internal.misc.Unsafe.getAndSetReference",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectPlain":   "jdk.internal.misc.Unsafe.weakCompareAndSetReferencePlain",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObject":        "jdk.internal.misc.Unsafe.weakCompareAndSetReference",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectAcquire": "jdk.internal.misc.Unsafe.weakCompareAndSetReferenceAcquire",
    "jdk.internal.misc.Unsafe.weakCompareAndSetObjectRelease": "jdk.internal.misc.Unsafe.weakCompareAndSetReferenceRelease",
}

# Deterministic JNI name aliases observed in bundled native libs.
METHOD_ALIASES = {
    "com.github.luben.zstd.Zstd.searchLengthMax": "com.github.luben.zstd.Zstd.searchLogMax",
    "com.github.luben.zstd.Zstd.searchLengthMin": "com.github.luben.zstd.Zstd.searchLogMin",
}

# Netty transport-native-unix: C registers netty_unix_limits_* onto
# LimitsStaticallyReferencedJniMethods: The binary extraction now correctly uses the
# full class name (io.netty.channel.unix.LimitsStaticallyReferencedJniMethods) so these
# legacy aliases pointing to the short "Limits." form are no longer needed.
# The cross-class alias (epoll.NativeStaticallyReferencedJniMethods -> unix.Limits*)
# is handled in the registered_method_map lookup fallback (step 3).

# ----------------------------
# JDK 8 ↔ JDK 9+ Package Renames
# ----------------------------
# In JDK 9, many internal APIs were moved from sun.* to jdk.internal.* (JEP 260)
# Bytecode compiled against JDK 9+ references jdk.internal.*, but JDK 8
# runtime only has sun.* symbols.
# This dictionary maps JDK 9+ names → JDK 8 names (verified against libjava.so)
JDK8_JDK9_PACKAGE_RENAMES = {
    # jdk.internal.misc.* → sun.misc.* (JEP 260)
    "jdk.internal.misc.Signal.handle0": "sun.misc.Signal.handle0",
    "jdk.internal.misc.Signal.raise0": "sun.misc.Signal.raise0",
    "jdk.internal.misc.VM.latestUserDefinedLoader0": "sun.misc.VM.latestUserDefinedLoader0",
    # Note: VM.getuid/geteuid/getgid/getegid are JDK 9+ only, no JDK 8 equivalent

    # jdk.internal.reflect.* → sun.reflect.* (JEP 260)
    "jdk.internal.reflect.ConstantPool.getUTF8At0": "sun.reflect.ConstantPool.getUTF8At0",
    "jdk.internal.reflect.ConstantPool.getIntAt0": "sun.reflect.ConstantPool.getIntAt0",
    "jdk.internal.reflect.ConstantPool.getLongAt0": "sun.reflect.ConstantPool.getLongAt0",
    "jdk.internal.reflect.ConstantPool.getFloatAt0": "sun.reflect.ConstantPool.getFloatAt0",
    "jdk.internal.reflect.ConstantPool.getDoubleAt0": "sun.reflect.ConstantPool.getDoubleAt0",
    "jdk.internal.reflect.ConstantPool.getClassAt0": "sun.reflect.ConstantPool.getClassAt0",
    "jdk.internal.reflect.ConstantPool.getStringAt0": "sun.reflect.ConstantPool.getStringAt0",
    # Note: areNestMates is JDK 11+ only, no JDK 8 equivalent
}

# ----------------------------
# JDK 8 ↔ JDK 9+ Method Name Changes
# ----------------------------
# Some methods were renamed in JDK 9+ (usually adding a "0" suffix for consistency)
# This maps JDK 9+ method names → JDK 8 method names
JDK8_JDK9_METHOD_RENAMES = {
    # Signal.findSignal0 (JDK 9+) → Signal.findSignal (JDK 8)
    "jdk.internal.misc.Signal.findSignal0": "sun.misc.Signal.findSignal",

    # Unsafe moved from sun.misc.Unsafe to jdk.internal.misc.Unsafe in JDK 9.
    # Several native entrypoint names also gained a trailing "0" wrapper in
    # JDK 9+, while the JDK 8 RegisterNatives table uses the public sun.misc
    # method name.  These aliases let bytecode extracted from JDK 9+ classes
    # resolve against a JDK 8 / Temurin 8 libjvm.so.
    "jdk.internal.misc.Unsafe.allocateMemory0": "sun.misc.Unsafe.allocateMemory",
    "jdk.internal.misc.Unsafe.freeMemory0": "sun.misc.Unsafe.freeMemory",
    "jdk.internal.misc.Unsafe.reallocateMemory0": "sun.misc.Unsafe.reallocateMemory",
    "jdk.internal.misc.Unsafe.setMemory0": "sun.misc.Unsafe.setMemory",
    "jdk.internal.misc.Unsafe.copyMemory0": "sun.misc.Unsafe.copyMemory",
    "jdk.internal.misc.Unsafe.objectFieldOffset0": "sun.misc.Unsafe.objectFieldOffset",
    "jdk.internal.misc.Unsafe.staticFieldOffset0": "sun.misc.Unsafe.staticFieldOffset",
    "jdk.internal.misc.Unsafe.staticFieldBase0": "sun.misc.Unsafe.staticFieldBase",
    "jdk.internal.misc.Unsafe.arrayBaseOffset0": "sun.misc.Unsafe.arrayBaseOffset",
    "jdk.internal.misc.Unsafe.arrayIndexScale0": "sun.misc.Unsafe.arrayIndexScale",
    "jdk.internal.misc.Unsafe.ensureClassInitialized0": "sun.misc.Unsafe.ensureClassInitialized",
    "jdk.internal.misc.Unsafe.shouldBeInitialized0": "sun.misc.Unsafe.shouldBeInitialized",
    "jdk.internal.misc.Unsafe.defineAnonymousClass0": "sun.misc.Unsafe.defineAnonymousClass",
    "jdk.internal.misc.Unsafe.compareAndSetInt": "sun.misc.Unsafe.compareAndSwapInt",
    "jdk.internal.misc.Unsafe.compareAndSetLong": "sun.misc.Unsafe.compareAndSwapLong",
    "jdk.internal.misc.Unsafe.compareAndSetObject": "sun.misc.Unsafe.compareAndSwapObject",
    "jdk.internal.misc.Unsafe.compareAndSetReference": "sun.misc.Unsafe.compareAndSwapObject",
    "jdk.internal.misc.Unsafe.getReference": "sun.misc.Unsafe.getObject",
    "jdk.internal.misc.Unsafe.putReference": "sun.misc.Unsafe.putObject",
    "jdk.internal.misc.Unsafe.getReferenceVolatile": "sun.misc.Unsafe.getObjectVolatile",
    "jdk.internal.misc.Unsafe.putReferenceVolatile": "sun.misc.Unsafe.putObjectVolatile",
}

for _unsafe_name in (
    "addressSize",
    "allocateInstance",
    "getBoolean",
    "getByte",
    "getChar",
    "getDouble",
    "getFloat",
    "getInt",
    "getIntVolatile",
    "getLong",
    "getLongVolatile",
    "getObject",
    "getObjectVolatile",
    "getShort",
    "loadFence",
    "pageSize",
    "park",
    "putBoolean",
    "putByte",
    "putChar",
    "putDouble",
    "putFloat",
    "putInt",
    "putLong",
    "putLongVolatile",
    "putObject",
    "putObjectVolatile",
    "putShort",
    "storeFence",
    "throwException",
    "unpark",
):
    JDK8_JDK9_METHOD_RENAMES.setdefault(
        f"jdk.internal.misc.Unsafe.{_unsafe_name}",
        f"sun.misc.Unsafe.{_unsafe_name}",
    )

# Reverse aliases for the opposite mixed-JDK case: bytecode/native_methods.txt
# contains JDK 8 sun.misc.Unsafe names, but the selected runtime libjvm.so is
# JDK 9+ and its RegisterNatives table contains jdk.internal.misc.Unsafe names.
SUN_UNSAFE_TO_JDK_INTERNAL = {
    "sun.misc.Unsafe.addressSize": "jdk.internal.misc.Unsafe.addressSize0",
    "sun.misc.Unsafe.allocateMemory": "jdk.internal.misc.Unsafe.allocateMemory0",
    "sun.misc.Unsafe.arrayBaseOffset": "jdk.internal.misc.Unsafe.arrayBaseOffset0",
    "sun.misc.Unsafe.arrayIndexScale": "jdk.internal.misc.Unsafe.arrayIndexScale0",
    "sun.misc.Unsafe.compareAndSwapInt": "jdk.internal.misc.Unsafe.compareAndSetInt",
    "sun.misc.Unsafe.compareAndSwapLong": "jdk.internal.misc.Unsafe.compareAndSetLong",
    "sun.misc.Unsafe.compareAndSwapObject": "jdk.internal.misc.Unsafe.compareAndSetObject",
    "sun.misc.Unsafe.copyMemory": "jdk.internal.misc.Unsafe.copyMemory0",
    "sun.misc.Unsafe.defineAnonymousClass": "jdk.internal.misc.Unsafe.defineAnonymousClass0",
    "sun.misc.Unsafe.defineClass": "jdk.internal.misc.Unsafe.defineClass0",
    "sun.misc.Unsafe.ensureClassInitialized": "jdk.internal.misc.Unsafe.ensureClassInitialized0",
    "sun.misc.Unsafe.freeMemory": "jdk.internal.misc.Unsafe.freeMemory0",
    "sun.misc.Unsafe.objectFieldOffset": "jdk.internal.misc.Unsafe.objectFieldOffset0",
    "sun.misc.Unsafe.reallocateMemory": "jdk.internal.misc.Unsafe.reallocateMemory0",
    "sun.misc.Unsafe.setMemory": "jdk.internal.misc.Unsafe.setMemory0",
    "sun.misc.Unsafe.shouldBeInitialized": "jdk.internal.misc.Unsafe.shouldBeInitialized0",
    "sun.misc.Unsafe.staticFieldBase": "jdk.internal.misc.Unsafe.staticFieldBase0",
    "sun.misc.Unsafe.staticFieldOffset": "jdk.internal.misc.Unsafe.staticFieldOffset0",
}

for _unsafe_name in (
    "allocateInstance",
    "fullFence",
    "getBoolean",
    "getByte",
    "getChar",
    "getDouble",
    "getFloat",
    "getInt",
    "getIntVolatile",
    "getLong",
    "getLongVolatile",
    "getObject",
    "getObjectVolatile",
    "getShort",
    "loadFence",
    "pageSize",
    "park",
    "putBoolean",
    "putByte",
    "putChar",
    "putDouble",
    "putFloat",
    "putInt",
    "putLong",
    "putLongVolatile",
    "putObject",
    "putObjectVolatile",
    "putShort",
    "storeFence",
    "throwException",
    "unpark",
):
    SUN_UNSAFE_TO_JDK_INTERNAL.setdefault(
        f"sun.misc.Unsafe.{_unsafe_name}",
        f"jdk.internal.misc.Unsafe.{_unsafe_name}",
    )

# ----------------------------
# ZIP/NIO Method Name Variants
# ----------------------------
# Some bytecode uses *BufferBytes / *BytesBytes native names while older JDK
# libzip.so exported only shorter symbols (inflateBytes, deflateBytes).  We map
# bytecode → short name for JVM tables, then try both names against nm-built
# method_to_jni (see jni_lookup_candidates in the main loop).
METHOD_NAME_VARIANTS = {
    # Inflater methods - BufferBytes variant → Bytes
    "java.util.zip.Inflater.inflateBufferBytes": "java.util.zip.Inflater.inflateBytes",
    "java.util.zip.Inflater.inflateBytesBytes": "java.util.zip.Inflater.inflateBytes",

    # Deflater methods - BufferBytes variant → Bytes
    "java.util.zip.Deflater.deflateBufferBytes": "java.util.zip.Deflater.deflateBytes",
    "java.util.zip.Deflater.deflateBytesBytes": "java.util.zip.Deflater.deflateBytes",
}

# ----------------------------
# HawtJNI → Eclipse SWT Callback Mapping
# ----------------------------
# HawtJNI (org.fusesource.hawtjni.runtime) uses Eclipse SWT's Callback class internally.
# The Java package is org.fusesource.hawtjni.runtime.Callback, but the JNI symbols
# are Java_org_eclipse_swt_internal_Callback_*.
HAWTJNI_SWT_CALLBACK_MAPPING = {
    "org.fusesource.hawtjni.runtime.Callback.bind": "org.eclipse.swt.internal.Callback.bind",
    "org.fusesource.hawtjni.runtime.Callback.getEnabled": "org.eclipse.swt.internal.Callback.getEnabled",
    "org.fusesource.hawtjni.runtime.Callback.getEntryCount": "org.eclipse.swt.internal.Callback.getEntryCount",
    "org.fusesource.hawtjni.runtime.Callback.getPlatform": "org.eclipse.swt.internal.Callback.getPlatform",
    "org.fusesource.hawtjni.runtime.Callback.reset": "org.eclipse.swt.internal.Callback.reset",
    "org.fusesource.hawtjni.runtime.Callback.setEnabled": "org.eclipse.swt.internal.Callback.setEnabled",
    "org.fusesource.hawtjni.runtime.Callback.unbind": "org.eclipse.swt.internal.Callback.unbind",
}

# Known JNA/JFFI-style wrappers that directly bridge to libc symbols.
# These methods generally do not expose Java_* JNI symbols with matching names.
DIRECT_LIBC_METHODS = {
    "org.apache.cassandra.utils.NativeLibraryLinux.getpid": "getpid",
    "org.apache.cassandra.utils.NativeLibraryLinux.close": "close",
    "org.apache.cassandra.utils.NativeLibraryLinux.mlockall": "mlockall",
    "org.apache.cassandra.utils.NativeLibraryLinux.fcntl": "fcntl",
    "org.apache.cassandra.utils.NativeLibraryLinux.fsync": "fsync",
    "org.apache.cassandra.utils.NativeLibraryLinux.strerror": "strerror",
    "org.apache.cassandra.utils.NativeLibraryLinux.posix_fadvise": "posix_fadvise",
    "org.apache.cassandra.utils.NativeLibraryLinux.open": "open",
    "org.apache.cassandra.utils.NativeLibraryLinux.munlockall": "munlockall",
    "net.openhft.posix.internal.jna.JNAPosixInterface.mmap": "mmap",
    "org.fusesource.jansi.internal.CLibrary.openpty": "openpty",  # PTY allocation (Jansi terminal)
}

DIRECT_JNI_BRIDGES = {
    # JDK I/O wrappers invoke private native *0 methods.
    "java.io.RandomAccessFile.length": "Java_java_io_RandomAccessFile_length0",
    "java.io.RandomAccessFile.readBytes": "Java_java_io_RandomAccessFile_readBytes0",
    "java.io.RandomAccessFile.writeBytes": "Java_java_io_RandomAccessFile_writeBytes0",
    "java.io.RandomAccessFile.setLength": "Java_java_io_RandomAccessFile_setLength0",
}

SOURCE_JNI_BRIDGES = {
    # Implemented in OpenJDK libjava native sources; symbols may be hidden.
    "java.lang.StrictMath.log": "Java_java_lang_StrictMath_log",
    "java.security.AccessController.getStackAccessControlContext": "Java_java_security_AccessController_getStackAccessControlContext",
    "java.security.AccessController.getInheritedAccessControlContext": "Java_java_security_AccessController_getInheritedAccessControlContext",
}


# Sigar high-level gather methods that map to native "Sigar_get*List" entrypoints.
SIGAR_LIST_BRIDGES = {
    "org.hyperic.sigar.FileSystem.gather": "Java_org_hyperic_sigar_Sigar_getFileSystemListNative",
    "org.hyperic.sigar.Who.gather": "Java_org_hyperic_sigar_Sigar_getWhoList",
    "org.hyperic.sigar.CpuInfo.gather": "Java_org_hyperic_sigar_Sigar_getCpuInfoList",
    "org.hyperic.sigar.NetRoute.gather": "Java_org_hyperic_sigar_Sigar_getNetRouteList",
    "org.hyperic.sigar.NetConnection.gather": "Java_org_hyperic_sigar_Sigar_getNetConnectionList",
}

UNSAFE_FENCE_METHODS = {
    "jdk.internal.misc.Unsafe.loadFence",
    "jdk.internal.misc.Unsafe.storeFence",
}

# ----------------------------
# Helpers
# ----------------------------

def is_elf(path: str) -> bool:
    """Return True if the file starts with the ELF magic bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def jni_to_java_method(jni_name: str):
    """
    Convert a JNI symbol name to its fully-qualified Java method name.

    KEY FIX: Strip the overload disambiguation suffix before processing.
    The JNI spec uses double-underscore (__) to separate the method name from
    the encoded argument signature when overloaded methods exist.

    Examples:
        Java_com_kenai_jffi_Foreign_getZeroTerminatedByteArrayChecked__J
            -> com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked
        Java_com_kenai_jffi_Foreign_getZeroTerminatedByteArrayChecked__JI
            -> com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked
        Java_java_lang_System_nanoTime
            -> java.lang.System.nanoTime
        Java_java_util_Map_00024Entry_getKey
            -> java.util.Map$Entry.getKey
        Java_com_sun_GTKEngine_native_1get_1gtk_1setting
            -> com.sun.GTKEngine.native_get_gtk_setting
        Java_com_kenai_jffi_Foreign_defineClass__Ljava_lang_String_2Ljava_lang_Object_2_3BII
            -> com.kenai.jffi.Foreign.defineClass
        Java_com_sun_jna_Native__1getPointer
            -> com.sun.jna.Native._getPointer     (__1 = separator + underscore escape, NOT overload)
        Java_com_sun_jna_Native__1getDirectBufferPointer
            -> com.sun.jna.Native._getDirectBufferPointer
    """
    if not jni_name.startswith("Java_"):
        return None

    mangled = jni_name[5:]

    # CRITICAL FIX: Strip overload suffix — double underscore marks the start of
    # the encoded argument type signature (e.g., __J, __JI, __Ljava_lang_String_2).
    # This suffix is NOT part of the Java method name and must be removed before
    # any other processing, otherwise __ becomes .. in the final output.
    #
    # BUG FIX: Must NOT strip at "__" when followed by JNI escape digits (0-3).
    # JNI escape sequences: _1 (underscore), _2 (semicolon), _3 (bracket), _0xxxx (unicode).
    # So "__1" is actually "_" (separator) + "_1" (literal underscore), NOT an overload
    # delimiter.  Example: Java_com_sun_jna_Native__1getPointer → _getPointer (not stripped).
    # We use a negative lookahead (?![0-3]) to skip these escape sequences.
    overload_match = re.search(r'__(?![0-3])', mangled)
    if overload_match:
        mangled = mangled[:overload_match.start()]

    # Step 1: Handle Unicode escapes (_0xxxx -> Unicode character)
    # Must be done BEFORE other replacements
    def unescape_unicode(match):
        return chr(int(match.group(1), 16))

    mangled = re.sub(r'_0([0-9a-fA-F]{4})', unescape_unicode, mangled)

    # Step 2: Handle escape sequences with temporary placeholders
    # CRITICAL: Must do this BEFORE replacing _ with .
    mangled = mangled.replace("_1", "\x00UNDERSCORE\x00")
    mangled = mangled.replace("_2", ";")
    mangled = mangled.replace("_3", "[")

    # Step 3: Replace remaining underscores with dots (package/class separators)
    mangled = mangled.replace("_", ".")

    # Step 4: Restore literal underscores
    mangled = mangled.replace("\x00UNDERSCORE\x00", "_")

    return mangled


def is_mangled_jni(jni_name: str) -> bool:
    """Return True if the JNI symbol uses escape sequences beyond simple underscores.
    i.e. _1 (literal underscore), _2 (semicolon), _3 (bracket),
    _0xxxx (unicode), or __ (overload suffix)."""
    if not jni_name.startswith("Java_"):
        return False
    raw = jni_name[5:]
    if re.search(r'__(?![0-3])', raw):      # overload suffix
        return True
    if re.search(r'_[0-3]', raw):            # _1 _2 _3 or _0xxxx escape
        return True
    return False


def load_defined_symbols(so_path: str, pattern: str) -> set:
    """
    Extract defined symbol names from an ELF shared library matching a regex pattern.
    Uses nm -D --defined-only to get only exported, defined symbols.
    """
    try:
        out = subprocess.check_output(
            ["nm", "-D", "--defined-only", so_path],
            universal_newlines=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception as e:
        print(f"WARN: nm failed on {so_path}: {e}", file=sys.stderr)
        return set()
    symset = set()
    rx = re.compile(pattern)
    for line in out.splitlines():
        m = rx.search(line)
        if m:
            symset.add(m.group(0))
    return symset


def ldd_paths(binary_path: str) -> list:
    """Discover all shared library dependencies of a binary via ldd."""
    try:
        out = subprocess.check_output(
            ["ldd", binary_path],
            universal_newlines=True,
            stderr=subprocess.DEVNULL,
        )
    except Exception:
        return []
    paths = []
    for line in out.splitlines():
        line = line.strip()
        if "=>" in line:
            right = line.split("=>", 1)[1].strip()
            cand = right.split(" ", 1)[0].strip()
            if cand.startswith("/") and os.path.exists(cand) and is_elf(cand):
                paths.append(cand)
        else:
            tok = line.split(" ", 1)[0]
            if tok.startswith("/") and os.path.exists(tok) and is_elf(tok):
                paths.append(tok)
    return paths


def collect_search_libs(seed_libs: list, extra_dirs: list) -> list:
    """
    Build a comprehensive list of ELF libraries to search for symbol definitions.

    Search order (first match wins in resolve_symbol_in_libs):
      1. Seed libraries (libjvm.so, libjava.so) — always checked first.
      2. Container-extracted libraries from extra_dirs (LIBS_*/) — these are the
         actual libraries inside the container and should take priority over
         host-system libraries resolved via ldd.
      3. Transitive ldd dependencies of the seed libraries — host-system fallback
         for symbols not found in the container extraction.
    """
    seen = set()
    out = []

    # 1. Seed libraries first (libjvm.so, libjava.so).
    for p in seed_libs:
        if p and os.path.exists(p) and p not in seen:
            seen.add(p)
            if is_elf(p):
                out.append(p)

    # 2. Container-extracted libraries (LIBS_*/) — preferred over system libs.
    for d in extra_dirs:
        if not os.path.isdir(d):
            continue
        for p in glob.glob(os.path.join(os.path.abspath(d), "**", "lib*.so*"), recursive=True):
            if p not in seen and os.path.isfile(p) and is_elf(p):
                out.append(p)
                seen.add(p)

    # 3. Transitive ldd dependencies of seed libs — host-system fallback.
    ldd_queue = [p for p in seed_libs if p and os.path.exists(p)]
    while ldd_queue:
        cur = ldd_queue.pop()
        if is_elf(cur):
            for dep in ldd_paths(cur):
                if dep not in seen:
                    seen.add(dep)
                    if is_elf(dep):
                        out.append(dep)
                        ldd_queue.append(dep)

    return out


def resolve_symbol_in_libs(symbol: str, libs: list):
    """
    Find which library in a collection actually defines a given symbol.
    Returns the path to the first library that defines it, or None.
    """
    global RESOLVE_SYMBOL_CALLS
    RESOLVE_SYMBOL_CALLS += 1
    for so in libs:
        symbols = get_library_symbol_index(so, require_full=False)
        if symbol in symbols:
            return so
        # Fallback to local/non-exported symbol index only if needed.
        symbols_full = get_library_symbol_index(so, require_full=True)
        if symbol in symbols_full:
            return so
    return None


LIB_SYMBOL_INDEX = {}
LIB_SYMBOL_INDEX_FULL = set()
NM_SUBPROCESS_CALLS = 0
RESOLVE_SYMBOL_CALLS = 0


def _add_symbol_and_alias(symbols: set, sym: str):
    symbols.add(sym)
    if "@" in sym:
        symbols.add(sym.split("@", 1)[0])


def get_library_symbol_index(so: str, require_full: bool = False) -> set:
    global NM_SUBPROCESS_CALLS
    cached = LIB_SYMBOL_INDEX.get(so)
    if cached is not None and (not require_full or so in LIB_SYMBOL_INDEX_FULL):
        return cached

    symbols = cached if cached is not None else set()
    commands = (
        [
            ["nm", "--defined-only", so],  # include local defined symbols
            ["nm", so],                    # broad fallback (handles stripped oddities)
        ]
        if cached is not None
        else [
            ["nm", "-D", "--defined-only", so],  # exported dynamic symbols first
        ]
    )

    for cmd in commands:
        try:
            NM_SUBPROCESS_CALLS += 1
            out = subprocess.check_output(
                cmd,
                universal_newlines=True,
                stderr=subprocess.DEVNULL,
            )
        except Exception:
            continue
        for line in out.splitlines():
            parts = line.split()
            if parts:
                _add_symbol_and_alias(symbols, parts[-1])
        if cached is None and symbols and not require_full:
            break

    LIB_SYMBOL_INDEX[so] = symbols
    if require_full:
        LIB_SYMBOL_INDEX_FULL.add(so)
    return symbols

# ----------------------------
# Discover libraries (.so) — filter to ELF only (recursive for JDK*/server/ layout)
# ----------------------------
so_paths: list = []
for lib_dir in LIB_DIRS:
    if not os.path.isdir(lib_dir):
        continue
    pattern = os.path.join(os.path.abspath(lib_dir), "**", "lib*.so*")
    for p in glob.glob(pattern, recursive=True):
        if os.path.isfile(p) and is_elf(p):
            so_paths.append(p)
so_paths = sorted(set(so_paths))



def find_libjvm():
    """
    Locate libjvm.so, preferring LIB_DIRS, then JAVA_HOME, then system paths.
    Prefer .../JDK<N>_LIBS/server/libjvm.so over a top-level libjvm.so in LIBS_*.
    """
    if JVM_SO and os.path.isfile(JVM_SO):
        return JVM_SO
    candidates = []
    for d in LIB_DIRS:
        for p in glob.glob(os.path.join(d, "**", "libjvm.so"), recursive=True):
            if os.path.isfile(p) and is_elf(p):
                candidates.append(p)

    def sort_key(path: str):
        path = path.replace("\\", "/")
        in_jdk_tree = "JDK" in path and "_LIBS" in path
        in_server = "/server/" in path
        # Lower tuple sorts first in Python -> prefer (False,) for in_jdk... wait we want JDK first.
        # (0,0) before (0,1) before (1,0): use (not in_jdk_tree, not in_server)
        return (not in_jdk_tree, not in_server, len(path))

    candidates.sort(key=sort_key)
    if candidates:
        return candidates[0]
    java_home = os.environ.get("JAVA_HOME")
    fallback = []
    if java_home:
        fallback += glob.glob(os.path.join(java_home, "lib", "server", "libjvm.so"))
        fallback += glob.glob(os.path.join(java_home, "**", "libjvm.so"), recursive=True)
    fallback += glob.glob("/usr/lib/jvm/**/lib/server/libjvm.so", recursive=True)
    fallback += glob.glob("/usr/lib/jvm/**/libjvm.so", recursive=True)
    fallback = [c for c in fallback if os.path.isfile(c) and is_elf(c)]
    return fallback[0] if fallback else None


libjvm_so = find_libjvm()

if not so_paths and not libjvm_so:
    print("ERROR: No ELF .so files found. Check LIB_DIRS/JAVA_HOME.", file=sys.stderr)
    sys.exit(1)

print("DEBUG: ELF libraries found:")
for p in so_paths:
    print(" -", p)
if libjvm_so:
    print(" - (JVM) ", libjvm_so)
else:
    print("WARN: libjvm.so not found; JVM_* validation will be skipped")

# ----------------------------
# Step 1: Build JNI mapping (Java_* symbols)
#
# KEY FIX: Use dict[str, list[tuple]] instead of dict[str, tuple] to handle
# overloaded methods. Multiple JNI symbols can map to the same Java method name
# (e.g., Java_*_getZeroTerminatedByteArrayChecked__J and __JI both map to
# com.kenai.jffi.Foreign.getZeroTerminatedByteArrayChecked). We store all of them
# and use the first one for output (they all live in the same .so).
# ----------------------------
method_to_jni: dict = {}  # str -> list[tuple[str, str]]

for so_path in so_paths:
    out_syms = load_defined_symbols(so_path, r"\bJava_[A-Za-z0-9_]+\b")
    for jni in out_syms:
        java_method = jni_to_java_method(jni)
        if java_method:
            if java_method not in method_to_jni:
                method_to_jni[java_method] = []
            method_to_jni[java_method].append((jni, so_path))

print(f"INFO: Built JNI map with {len(method_to_jni)} unique Java method entries")

# Show a few examples including overloaded ones
overloaded = {k: v for k, v in method_to_jni.items() if len(v) > 1}
print(f"INFO: {len(overloaded)} methods have overloaded JNI variants")
for method, variants in list(overloaded.items())[:5]:
    print(f"  {method}:")
    for sym, lib in variants:
        print(f"    {sym} ({os.path.basename(lib)})")

# ----------------------------
# Step 1.7: JNI Dynamic Bindings (extract_jni_bindings.py output per lib tree)
# ----------------------------
def _auto_extract_jni_bindings(libs_dir: str, output_dir_path: str) -> bool:
    """
    Run extract_jni_bindings.py against `libs_dir` and write
    jni_dynamic_bindings.txt + jni_dynamic_summary.txt into `output_dir_path`.

    Returns True iff jni_dynamic_bindings.txt is present (non-empty) afterwards.
    """
    if not libs_dir or not os.path.isdir(libs_dir):
        return False

    script_path = os.path.join(SCRIPT_DIR, "extract_jni_bindings.py")
    if not os.path.isfile(script_path):
        print(f"INFO: extract_jni_bindings.py not found at {script_path}; "
              f"skipping JNI auto-extraction.")
        return False

    os.makedirs(os.path.abspath(output_dir_path), exist_ok=True)
    out_path = os.path.join(output_dir_path, "jni_dynamic_bindings.txt")
    print(f"INFO: Auto-extracting JNI dynamic bindings from {libs_dir} -> {out_path}")
    try:
        proc = subprocess.run(
            [sys.executable, script_path,
             "--libs-dir", libs_dir,
             "--output-dir", output_dir_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        print(f"WARNING: Failed to invoke {script_path}: {e}")
        return False

    if proc.returncode != 0:
        tail = "\n  ".join((proc.stderr or "").strip().splitlines()[-5:])
        print(f"INFO: JNI auto-extraction failed for {libs_dir} "
              f"(exit {proc.returncode}); jni_dynamic table will be empty.\n  {tail}")
        return False

    # extract_jni_bindings.py prints a one-line summary to stdout; preserve it.
    summary = (proc.stdout or "").strip()
    if summary:
        for line in summary.splitlines():
            print(f"  {line}")

    return os.path.isfile(out_path) and os.path.getsize(out_path) > 0


def _auto_extract_registernatives_binary(so_files: list, output_dir_path: str) -> str:
    """
    Run extract_registernatives_binary.py against one or more .so files
    (typically libjvm.so and libjava.so) and write jvm_dynamic_mapping.txt
    into `output_dir_path`.

    Returns the path to jvm_dynamic_mapping.txt if successful, empty string otherwise.
    """
    valid_so = [p for p in so_files if p and os.path.isfile(p)]
    if not valid_so:
        return ""

    script_path = os.path.join(PROJECT_ROOT, "scripts", "extract_registernatives_binary.py")
    if not os.path.isfile(script_path):
        print(f"INFO: extract_registernatives_binary.py not found at {script_path}; "
              f"skipping RegisterNatives binary extraction.")
        return ""

    os.makedirs(os.path.abspath(output_dir_path), exist_ok=True)
    out_path = os.path.join(output_dir_path, "jvm_dynamic_mapping.txt")
    so_names = ", ".join(os.path.basename(p) for p in valid_so)
    print(f"INFO: Extracting RegisterNatives tables from [{so_names}] -> {out_path}")
    try:
        proc = subprocess.run(
            [sys.executable, script_path] + valid_so + ["-o", out_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        print(f"WARNING: Failed to invoke {script_path}: {e}")
        return ""

    if proc.returncode != 0:
        tail = "\n  ".join((proc.stderr or "").strip().splitlines()[-5:])
        print(f"INFO: RegisterNatives binary extraction failed "
              f"(exit {proc.returncode}); will fall back to JVM_SRC source scan.\n  {tail}")
        return ""

    summary = (proc.stderr or "").strip()
    if summary:
        for line in summary.splitlines()[-5:]:
            print(f"  {line}")

    if os.path.isfile(out_path) and os.path.getsize(out_path) > 0:
        return out_path
    return ""


def discover_jni_dynamic_binding_paths(output_dir_path: str, primary_lib_dirs: list) -> list:
    """
    Resolve jni_dynamic_bindings.txt strictly from OUTPUTS_DIR/<IMG_NAME>/.

    If that file is missing, auto-generate it by running extract_jni_bindings.py
    against the *first* user-provided LIB_DIR (LIBS_<IMG_NAME>/).  This keeps
    the binding table tied to the exact .so files the container actually ships,
    matching the per-container scoping rule used for jvm_dynamic_mapping.txt.

    The previous auto-walk over cwd, LIBS_<IMG_NAME>/, and the supplemental
    NON-JDK third-party bundles (netty_libs / netty_libs_all / hawtjni_libs /
    hadoop_libs / hadoop_ec_downloads) was leaking Netty/Hadoop/SWT bindings
    from versions the container does not actually ship.

    `JNI_DYNAMIC_BINDING_DIRS` is preserved purely as an explicit opt-in escape
    hatch for callers that need to layer in extra binding files; it is not
    populated by anything in this script.

    Returns a deduplicated, ordered list of absolute paths.
    """
    paths = []
    seen = set()

    def add_candidate(raw: str):
        if not raw:
            return
        ap = os.path.abspath(raw)
        if ap in seen:
            return
        if os.path.isfile(ap):
            seen.add(ap)
            paths.append(ap)

    primary_path = os.path.join(output_dir_path, "jni_dynamic_bindings.txt")
    if not os.path.isfile(primary_path) and primary_lib_dirs:
        _auto_extract_jni_bindings(primary_lib_dirs[0], output_dir_path)

    add_candidate(primary_path)

    # Also extract JNI dynamic bindings from libjffi if present
    for _lib_dir in primary_lib_dirs:
        for _jffi_so in glob.glob(os.path.join(_lib_dir, "**", "libjffi*.so*"), recursive=True):
            if os.path.isfile(_jffi_so) and is_elf(_jffi_so):
                _jffi_out_dir = os.path.join(output_dir_path, "jffi_bindings")
                _jffi_binding = os.path.join(_jffi_out_dir, "jni_dynamic_bindings.txt")
                if not os.path.isfile(_jffi_binding):
                    print(f"INFO: Auto-extracting JNI dynamic bindings from libjffi: {_jffi_so}")
                    _auto_extract_jni_bindings(_lib_dir, _jffi_out_dir)
                add_candidate(_jffi_binding)
                break  # one extraction per lib_dir is enough

    env_jni_dyn = os.environ.get("JNI_DYNAMIC_BINDING_DIRS")
    if env_jni_dyn:
        for part in env_jni_dyn.split(os.pathsep):
            d = part.strip()
            if d:
                add_candidate(os.path.join(d, "jni_dynamic_bindings.txt"))
    return paths


def resolve_lib_for_jni_binding(lib_name: str, bindings_file: str, so_paths: list):
    """
    Prefer the .so next to the jni_dynamic_bindings.txt that referenced it (same tree),
    then fall back to any matching basename in so_paths.
    """
    bind_dir = os.path.dirname(os.path.abspath(bindings_file))
    local = os.path.join(bind_dir, lib_name)
    if os.path.isfile(local):
        return local
    for so in so_paths:
        if os.path.basename(so) == lib_name:
            return so
    return None


def load_jni_dynamic_bindings(binding_paths: list, so_paths: list) -> dict:
    """
    Load JNI dynamic bindings from extract_jni_bindings.py output files.
    File format: libfoo.so|com.example.Class.method|(I)V|native_symbol|HIGH_CONF
    Returns: dict[java_method] -> (jni_symbol, library_path)

    Conflict resolution per java_method (lower priority value wins):
      0..N-1  : LIBS_<IMG_NAME>/  (PRIMARY_LIB_DIRS, in order)
      999     : unresolved or path outside the project tree

    Tie-breaker at the same priority level: keep the first row encountered
    (preserves file-order intent within a single source).
    """
    bindings: dict = {}
    bindings_priority: dict = {}
    if not binding_paths:
        print("INFO: No jni_dynamic_bindings.txt paths discovered (optional).")
        return bindings

    def upsert(java_method, jni_symbol, lib_path):
        if not lib_path:
            return
        new_prio = lib_priority(lib_path)
        prev_prio = bindings_priority.get(java_method)
        if prev_prio is None or new_prio < prev_prio:
            bindings[java_method] = (jni_symbol, lib_path)
            bindings_priority[java_method] = new_prio

    for path in binding_paths:
        n_before = len(bindings)
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split("|")
                if len(parts) < 4:
                    continue
                lib_name, java_method, _signature, jni_symbol = parts[:4]
                lib_path = resolve_lib_for_jni_binding(lib_name, path, so_paths)
                # extract_jni_bindings records the path basename at extraction time; images
                # often ship the same ELF under a different name (e.g. shaded libnetty_epoll_*.jar.so
                # vs libnetty_transport_native_epoll_x86_64.so).  Fall back to symbol ownership.
                if lib_path is None and jni_symbol:
                    lib_path = resolve_symbol_in_libs(jni_symbol, so_paths)
                upsert(java_method, jni_symbol, lib_path)
        added = len(bindings) - n_before
        print(f"INFO: JNI dynamic bindings file {path} (+{added} new methods, {len(bindings)} total)")

    return bindings


jni_dynamic_binding_paths = discover_jni_dynamic_binding_paths(output_dir, PRIMARY_LIB_DIRS)
jni_dynamic_map = load_jni_dynamic_bindings(jni_dynamic_binding_paths, so_paths)
# SYM_INFER / extractor casing may differ from bytecode (e.g. Linuxsocket vs LinuxSocket).
jni_dynamic_lower_index = {}
for _fqcn in jni_dynamic_map:
    jni_dynamic_lower_index.setdefault(_fqcn.lower(), _fqcn)

# ----------------------------
# Step 2: Source-based scan of JNINativeMethod tables (optional)
# ----------------------------


# Map of well-known HotSpot/libjava source file basenames (CASE-INSENSITIVE)
# to their corresponding fully-qualified Java class names.
# Needed because HotSpot filenames (e.g., unsafe.cpp, methodHandles.cpp) don't
# follow the standard Java_pkg_Class naming convention.
_HOTSPOT_FILE_CLASS_MAP = {
    # hotspot/share/prims/
    "unsafe":           "jdk.internal.misc.Unsafe",
    "methodhandles":    "java.lang.invoke.MethodHandleNatives",
    "perf":             "jdk.internal.perf.Perf",
    "scopedmemoryaccess": "jdk.internal.misc.ScopedMemoryAccess",
    # libjava files
    "class":            "java.lang.Class",
    "system":           "java.lang.System",
    "thread":           "java.lang.Thread",
    "classloader":      "java.lang.ClassLoader",
    "runtime":          "java.lang.Runtime",
    "object":           "java.lang.Object",
    "string":           "java.lang.String",
    "throwable":        "java.lang.Throwable",
    "stacktraceelement": "java.lang.StackTraceElement",
    "processenvironment": "java.lang.ProcessEnvironment",
    "package":          "java.lang.Package",
    "module":           "java.lang.Module",
    "float":            "java.lang.Float",
    "double":           "java.lang.Double",
    "strictmath":       "java.lang.StrictMath",
    "vm":               "jdk.internal.misc.VM",
    "signal":           "jdk.internal.misc.Signal",
    "accesscontroller": "java.security.AccessController",
    "objectoutputstream": "java.io.ObjectOutputStream",
    "objectinputstream":  "java.io.ObjectInputStream",
    "mappedbytebuffer":   "java.nio.MappedByteBuffer",
}


def infer_java_class_from_path(filepath: str):
    """
    Infer the fully-qualified Java class name from a native source file path.
    Uses filename pattern, directory structure, HotSpot file map, and file
    content as fallbacks.
    """
    path = filepath.replace("\\", "/")
    base = os.path.splitext(os.path.basename(path))[0]

    # Pattern 1: Standard libjava naming — e.g., java_lang_Thread_isAlive.c
    m = re.match(r'^(java|jdk)_([A-Za-z0-9_]+)_([A-Za-z0-9_$]+)$', base)
    if m:
        root, pkg_part, cls = m.groups()
        pkg = pkg_part.replace('_', '.')
        return f"{root}.{pkg}.{cls}"

    # Pattern 2: Directory-based — e.g., .../native/libjava/Thread.c
    parts = path.split("/")
    if "java" in parts:
        try:
            i = parts.index("java")
            if i + 2 < len(parts):
                pkg = parts[i + 1]
                cls = os.path.splitext(parts[i + 2])[0]
                if re.match(r"^[a-z][a-z0-9_]*$", pkg) and re.match(r"^[A-Z][A-Za-z0-9_$]*$", cls):
                    return f"java.{pkg}.{cls}"
        except ValueError:
            pass

    # Pattern 3: Well-known HotSpot/libjava file names (case-insensitive)
    mapped = _HOTSPOT_FILE_CLASS_MAP.get(base.lower())
    if mapped:
        return mapped

    # Pattern 4: Content-based fallback — scan first 4K for a FQCN
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read(4096)
        m2 = re.search(r'\b((java|jdk)\.[a-z0-9_.]+\.[A-Za-z0-9_$]+)\b', text)
        if m2:
            return m2.group(1)
    except Exception:
        pass

    return None


def scan_native_tables(src_root: str):
    """
    Parse OpenJDK source code to extract JNINativeMethod registration tables.
    Returns two dicts:
      - jvm_map:  method -> JVM_* symbol
      - reg_map:  method -> non-JVM C function name
    """
    jvm_map, reg_map = {}, {}
    if not src_root or not os.path.isdir(src_root):
        return jvm_map, reg_map

    # Match JNINativeMethod table entries in three common cast styles:
    #   1)  (void *)&JVM_StartThread           — libjava C files (Thread.c, etc.)
    #   2)  FN_PTR(Unsafe_AllocateMemory0)     — HotSpot C++ files (unsafe.cpp, methodHandles.cpp)
    #   3)  CAST_FROM_FN_PTR(void*, &target)   — rare, but FN_PTR expands to this
    entry_rx = re.compile(
        r'''\{\s*
            (?:CC\s*)?"(?P<name>[A-Za-z0-9_]+)"\s*,\s*
            (?P<sig>[^,]+?)\s*,\s*
            (?:
                \(void\s*\*\)\s*&?(?P<target1>[A-Za-z0-9_]+)
              | FN_PTR\((?P<target2>[A-Za-z0-9_]+)\)
              | CAST_FROM_FN_PTR\([^,]+,\s*&?(?P<target3>[A-Za-z0-9_]+)\)
            )
            \s*\}''',
        re.VERBOSE
    )

    for root, _, files in os.walk(src_root):
        for fn in files:
            if not fn.endswith((".c", ".cc", ".cpp", ".cxx")):
                continue
            path = os.path.join(root, fn)
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    text = f.read()
            except Exception:
                continue

            clazz = infer_java_class_from_path(path)

            for m in entry_rx.finditer(text):
                name   = m.group("name")
                target = m.group("target1") or m.group("target2") or m.group("target3")
                use_class = clazz
                if not use_class:
                    # infer_java_class_from_path handles HotSpot files via
                    # _HOTSPOT_FILE_CLASS_MAP; if it still returns None, skip.
                    continue
                key = f"{use_class}.{name}"
                if target.startswith("JVM_"):
                    jvm_map.setdefault(key, target)
                else:
                    reg_map.setdefault(key, target)

    return jvm_map, reg_map


# ----------------------------
# Step 2.5: Extract RegisterNatives tables directly from the container's
# libjvm.so binary using extract_registernatives_binary.py.
#
# The scan_native_tables() source-tree walk remains as a fallback — but
# the preferred flow is:
#   1) Run extract_registernatives_binary.py on LIBS_<IMG_NAME>/libjvm.so
#   2) Write output to OUTPUTS_<IMG_NAME>/jvm_dynamic_mapping.txt
#   3) Load the pipe-delimited mapping, intersecting native_symbol with
#      what `nm libjvm.so` actually defines to drop phantom entries.
# ----------------------------


def load_jdk_mapping_file(mapping_file, libjvm_path):
    """
    Parse a pipe-delimited mapping file (extract_registernatives_binary.py
    output) and return (jvm_map, registered_map) just like scan_native_tables().

    Each row whose declared library is libjvm.so must have its native_symbol
    actually defined in *libjvm_path* (verified via the nm-backed symbol
    index).  Rows that reference symbols missing from this build are dropped
    so we don't emit phantom JVM_* / registered hits for natives that simply
    don't exist in the container's JVM.
    """
    jvm_map, reg_map = {}, {}
    if not os.path.isfile(mapping_file):
        return jvm_map, reg_map, 0, 0

    libjvm_syms = set()
    if libjvm_path and os.path.isfile(libjvm_path):
        # The two-stage symbol index in get_library_symbol_index() only
        # extends to local (non-exported) symbols when the dynamic cache is
        # already warm.  Many HotSpot natives (WB_*, Unsafe_*, VectorSupport_*,
        # PUH_*, jfr_*) are local-only, so we must call once to seed the
        # dynamic set and a second time to fold in the full nm output.
        get_library_symbol_index(libjvm_path, require_full=False)
        libjvm_syms = get_library_symbol_index(libjvm_path, require_full=True)

    kept = 0
    dropped = 0
    with open(mapping_file, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) < 4:
                continue
            lib_name, java_method, _signature, native_sym = parts[:4]
            if lib_name == "libjvm.so" and libjvm_syms and native_sym not in libjvm_syms:
                dropped += 1
                continue
            if native_sym.startswith("JVM_"):
                jvm_map.setdefault(java_method, native_sym)
            else:
                reg_map.setdefault(java_method, native_sym)
            kept += 1
    return jvm_map, reg_map, kept, dropped


jvm_method_map, registered_method_map = {}, {}
_jdk_mapping_loaded_from = None

if libjvm_so:
    _rn_so_files = [libjvm_so]
    _rn_seen_real = {os.path.realpath(libjvm_so)}
    for _p in so_paths:
        _bn = os.path.basename(_p)
        if _bn.startswith("libjava.so") or _bn.startswith("libnetty") or _bn.startswith("libjffi"):
            _real = os.path.realpath(_p)
            if _real not in _rn_seen_real:
                _rn_seen_real.add(_real)
                _rn_so_files.append(_p)
    _rn_mapping_path = _auto_extract_registernatives_binary(_rn_so_files, output_dir)
    if _rn_mapping_path:
        jvm_method_map, registered_method_map, kept, dropped = (
            load_jdk_mapping_file(_rn_mapping_path, libjvm_so)
        )
        print(
            f"INFO: Loaded RegisterNatives binary mapping from {_rn_mapping_path}: "
            f"{len(jvm_method_map)} JVM_* + {len(registered_method_map)} "
            f"registered (kept {kept}, dropped {dropped} not in "
            f"{os.path.basename(libjvm_so)})"
        )
        _jdk_mapping_loaded_from = _rn_mapping_path

# Fallback: if binary extraction produced nothing, walk the source tree the old way.
if not jvm_method_map and not registered_method_map:
    try:
        jvm_method_map, registered_method_map = scan_native_tables(JVM_SRC_NORM)
        if JVM_SRC_NORM and os.path.isdir(JVM_SRC_NORM):
            print(f"INFO: Source scan found {len(jvm_method_map)} JVM_* entries "
                  f"and {len(registered_method_map)} registered entries.")
        else:
            shown = JVM_SRC_NORM or JVM_SRC or "<empty>"
            print(f"INFO: JVM_SRC not set (or missing). Skipping source-based mapping. ({shown})")
    except Exception as e:
        print(f"WARN: JVM source scan failed: {e}", file=sys.stderr)
        jvm_method_map, registered_method_map = {}, {}

# ----------------------------
# Step 3: Validate JVM_* symbols and prepare search library list
# ----------------------------
available_jvm_symbols = set()
if libjvm_so:
    available_jvm_symbols = load_defined_symbols(libjvm_so, r"\bJVM_[A-Za-z0-9_]+\b")

seed_libs = []
if libjvm_so:
    seed_libs.append(libjvm_so)
for p in so_paths:
    bn = os.path.basename(p)
    if bn.startswith("libjava.so") or bn.startswith("libjffi"):
        seed_libs.append(p)

search_libs = collect_search_libs(seed_libs, LIB_DIRS)

print(f"INFO: Classifying {len(methods)} methods...")

# ----------------------------
# Step 4.5: Platform-exclusion keywords
# ----------------------------
# Methods containing these substrings target non-Linux platforms and will
# never execute inside a Linux container.  Tag them early so we skip the
# expensive symbol lookups and keep them out of the "NOT_FOUND" bucket.
PLATFORM_EXCLUDE_KEYWORDS = [
    ".kqueue.",             # macOS/BSD kqueue API  (io.netty.channel.kqueue.*)
    ".win32.",              # Windows APIs          (org.hyperic.sigar.win32.*)
    "NativeLibraryDarwin",  # macOS Cassandra       (o.a.c.utils.NativeLibraryDarwin.*)
    "BsdSocket.",           # BSD-specific Netty    (io.netty.channel.kqueue.BsdSocket.*)
    "Foreign.VirtualAlloc", # Windows VirtualAlloc  (com.kenai.jffi.Foreign.VirtualAlloc)
    "Foreign.VirtualFree",  # Windows VirtualFree   (com.kenai.jffi.Foreign.VirtualFree)
    "Foreign.VirtualProtect",# Windows VirtualProtect(com.kenai.jffi.Foreign.VirtualProtect)
    "jansi.internal.Kernel32", # Windows console APIs  (org.fusesource.jansi.internal.Kernel32.*)
    "jline.nativ.Kernel32",  # Windows JLine terminal (org.jline.nativ.Kernel32.*)
    "getWindowsDirectory",  # Windows Kerberos      (sun.security.krb5.Config.getWindowsDirectory)
    "SCDynamicStoreConfig", # macOS Kerberos        (sun.security.krb5.SCDynamicStoreConfig.*)
    "WindowsDirectory.",    # Windows Lucene native (org.apache.lucene.store.WindowsDirectory.*)
    "_getGlyphImageFromWindows", # Windows font rendering (sun.font.FileFontStrike.*)
    "tomcat.jni.Registry.",  # Windows Registry API  (org.apache.tomcat.jni.Registry.*)
    "jline.WindowsTerminal.", # Windows terminal API  (jline.WindowsTerminal.*)
    "log4j.nt.NTEventLogAppender.", # Windows NT Event Log (org.apache.log4j.nt.NTEventLogAppender.*)
]


def is_platform_excluded(method: str):
    """Return the matched keyword if *method* is platform-specific, else None."""
    for kw in PLATFORM_EXCLUDE_KEYWORDS:
        if kw in method:
            return kw
    return None


# ----------------------------
# Step 5: Classify each method
# ----------------------------
found_platform   = 0
not_found_count  = 0
count_jni_direct = 0  # Java_* exported JNI symbols (tag JNI)
count_jni_mangled = 0  # subset of JNI that required escape decoding (_1, $, __, etc.)
count_netty = 0  # NM fallback: unix.Socket / internal.tcnative / channel.epoll (tag NETTY)
count_jvm = 0
count_registered = 0
count_intrinsic = 0
# JNI_DYNAMIC (jni_dynamic_bindings.txt).
count_jni_dynamic_bindings = 0


def try_bridge_resolve(original: str, sym: str, tag: str, libs: list, out_file):
    owner = resolve_symbol_in_libs(sym, libs)
    if tag == "SIGAR_LIST_BRIDGE":
        # #region agent log
        debug_log("sigar-bridge-resolve", "H1", "evaluated SIGAR bridge symbol owner", {
            "original": original,
            "symbol": sym,
            "owner": owner,
            "libsCount": len(libs),
        })
        # #endregion
    if owner:
        emit_result(out_file, owner, original, original, sym, tag)
        return True
    out_file.write(f"{original} -> {sym} [{tag}? UNRESOLVED]\n")
    return False


def alias_tag(original: str, lookup: str) -> str:
    return f" (alias of {lookup})" if lookup != original else ""


# Render the owning library so that anything inside the project tree
# (e.g. <repo>/LIBS_cassandra_5.0.6-bookworm/libnetty_...so)
# becomes a project-relative path (LIBS_cassandra_5.0.6-bookworm/libnetty_...so),
# while system / ldd-resolved libs (e.g. /lib/x86_64-linux-gnu/libpthread.so.0)
# stay as bare basenames.
def display_lib_path(owner) -> str:
    if not owner:
        return "libjvm.so"
    abs_owner = os.path.abspath(owner)
    try:
        rel = os.path.relpath(abs_owner, PROJECT_ROOT)
    except ValueError:
        return os.path.basename(abs_owner)
    if rel == ".." or rel.startswith(".." + os.sep):
        return os.path.basename(abs_owner)
    return rel


def emit_result(out_file, owner: str, original: str, lookup: str, sym: str, tag: str, note: str = ""):
    # Virtual classifications such as [INTRINSIC] have no real library and
    # no native symbol (the JIT inlines them).  Emit them without a synthetic
    # "libjvm.so:" prefix so they read as bare:
    #     jdk.internal.misc.Unsafe.putFloatVolatile [INTRINSIC]
    if owner is None and sym is None:
        out_file.write(f"{original} [{tag}]{note}{alias_tag(original, lookup)}\n")
        return 1 if lookup != original else 0
    owner_display = display_lib_path(owner)
    if sym:
        out_file.write(f"{owner_display}:{original} -> {sym} [{tag}]{note}{alias_tag(original, lookup)}\n")
    else:
        out_file.write(f"{owner_display}:{original} [{tag}]{note}{alias_tag(original, lookup)}\n")
    return 1 if lookup != original else 0


def resolve_fence_fallback(lookup: str, libs: list):
    if lookup not in UNSAFE_FENCE_METHODS:
        return None
    owner = resolve_symbol_in_libs("Unsafe_FullFence", libs)
    if not owner:
        return None
    return owner, "Unsafe_FullFence"

with open(detailed_output_file, "w", encoding="utf-8") as out:
    for method in methods:

        # ----- 0) Handle [INTRINSIC] tag in input -----
        if method.endswith(" [INTRINSIC]"):
            clean_method = method.replace(" [INTRINSIC]", "")
            out.write(f"{clean_method} [INTRINSIC]\n")
            count_intrinsic += 1
            continue

        # ----- 0) Platform-excluded (win32, kqueue, Darwin) -----
        excl_kw = is_platform_excluded(method)
        if excl_kw:
            out.write(f"{method}: PLATFORM_EXCLUDED ({excl_kw})\n")
            found_platform += 1
            continue

        # ----- 0.5) Unsafe legacy-name alias resolution -----
        # If this is a renamed Unsafe method (JDK <14 name), resolve via the
        # new name.  We keep 'original' for output and use 'lookup' for all
        # subsequent lookups.
        original = method
        lookup = UNSAFE_RENAMED.get(method, method)
        lookup = METHOD_ALIASES.get(lookup, lookup)

        # Save lookup before zip/buffer JNI name variants so we can try both the
        # canonical short name (inflateBytes) and the bytecode-native long name
        # (inflateBytesBytes) against nm.  JDK 25+ libzip often exports only the
        # long JNI symbols; older JDKs export the short ones.
        pre_zip_variants_lookup = lookup

        # Apply JDK 8 ↔ JDK 9+ compatibility mappings in priority order:
        # 1. Method name variants (bytecode-level differences)
        # 2. JDK method renames (package + method name changes)
        # 3. JDK package renames (package-only changes)
        # 4. HawtJNI → Eclipse SWT Callback mapping
        lookup = METHOD_NAME_VARIANTS.get(lookup, lookup)
        lookup = JDK8_JDK9_METHOD_RENAMES.get(lookup, lookup)
        lookup = JDK8_JDK9_PACKAGE_RENAMES.get(lookup, lookup)
        lookup = HAWTJNI_SWT_CALLBACK_MAPPING.get(lookup, lookup)
        compat_lookup_candidates = []
        for _cand in (original, lookup):
            if _cand not in compat_lookup_candidates:
                compat_lookup_candidates.append(_cand)
        reverse_unsafe_lookup = SUN_UNSAFE_TO_JDK_INTERNAL.get(lookup)
        if reverse_unsafe_lookup and reverse_unsafe_lookup not in compat_lookup_candidates:
            compat_lookup_candidates.append(reverse_unsafe_lookup)

        # ----- 1) JNI direct hit (Java_* symbols) -----
        jni_lookup_candidates = [lookup]
        if lookup != pre_zip_variants_lookup:
            jni_lookup_candidates.append(pre_zip_variants_lookup)

        jni_map_key = None
        for cand in jni_lookup_candidates:
            if cand in method_to_jni:
                jni_map_key = cand
                break

        if jni_map_key is not None:
            jni_sym, so_path = method_to_jni[jni_map_key][0]
            if jni_map_key == "org.hyperic.sigar.Sigar.getFileSystemListNative":
                # #region agent log
                debug_log("sigar-jni-direct", "H2", "direct JNI mapping found for Sigar.getFileSystemListNative", {
                    "lookup": jni_map_key,
                    "jniSymbol": jni_sym,
                    "owner": so_path,
                })
                # #endregion
            emit_result(out, so_path, original, jni_map_key, jni_sym, "JNI")
            count_jni_direct += 1
            if is_mangled_jni(jni_sym):
                count_jni_mangled += 1
            continue

        # ----- 1.2) JNI Dynamic Bindings (RegisterNatives tables from extract_jni_bindings.py) -----
        jni_dyn_key = None
        for cand in iter_jni_dynamic_lookup_keys(original, lookup, shaded_netty_prefixes):
            if cand in jni_dynamic_map:
                jni_dyn_key = cand
                break
            alt = jni_dynamic_lower_index.get(cand.lower())
            if alt is not None:
                jni_dyn_key = alt
                break
        if jni_dyn_key is not None:
            jni_dyn_sym, so_path = jni_dynamic_map[jni_dyn_key]
            emit_result(out, so_path, original, jni_dyn_key, jni_dyn_sym, "JNI_DYNAMIC")
            count_jni_dynamic_bindings += 1
            continue

        # ----- 1.3) Netty unix.Socket — nm fallback for dynamically registered JNI ---
        sock_nm = try_netty_unix_socket_nm_fallback(original, lookup, shaded_netty_prefixes, search_libs)
        if sock_nm:
            so_path, sym, matched_java = sock_nm
            emit_result(out, so_path, original, matched_java, sym, "NETTY")
            count_netty += 1
            continue

        # ----- 1.4) Netty internal.tcnative — nm fallback (netty_internal_tcnative_Class_method) -----
        tcn_nm = try_netty_internal_tcnative_nm_fallback(original, lookup, shaded_netty_prefixes, search_libs)
        if tcn_nm:
            so_path, sym, matched_java = tcn_nm
            emit_result(out, so_path, original, matched_java, sym, "NETTY")
            count_netty += 1
            continue

        # ----- 1.5) Netty channel.epoll — nm fallback (netty_epoll_<classtoken>_method) -----
        ep_nm = try_netty_channel_epoll_nm_fallback(original, lookup, shaded_netty_prefixes, search_libs)
        if ep_nm:
            so_path, sym, matched_java = ep_nm
            emit_result(out, so_path, original, matched_java, sym, "NETTY")
            count_netty += 1
            continue

        # ----- 2) JVM_* via source tables -----
        jvm_sym = None
        jvm_lookup = lookup
        for cand in compat_lookup_candidates:
            jvm_sym = jvm_method_map.get(cand)
            if jvm_sym:
                jvm_lookup = cand
                break
            match = re.match(r'^(.+?)([a-z][a-zA-Z0-9_]*)\(', cand)
            if match:
                lookup_key = f"{match.group(1)}.{match.group(2)}"
                jvm_sym = jvm_method_map.get(lookup_key)
                if jvm_sym:
                    jvm_lookup = lookup_key
                    break

        if jvm_sym:
            tag = "JVM"
            if libjvm_so and (jvm_sym not in available_jvm_symbols):
                tag = "JVM? NOT_IN_THIS_LIB"
            emit_result(out, libjvm_so, original, jvm_lookup, jvm_sym, tag)
            count_jvm += 1
            continue

        # ----- 2.5) JVM built-in natives (well-known JVM_* functions) -----
        builtin_sym = None
        builtin_lookup = lookup
        for cand in compat_lookup_candidates:
            builtin_sym = JVM_BUILTIN_NATIVES.get(cand)
            if builtin_sym:
                builtin_lookup = cand
                break
        if builtin_sym:
            tag = "JVM"
            if libjvm_so and (builtin_sym not in available_jvm_symbols):
                tag = "JVM? NOT_IN_THIS_LIB"
            emit_result(out, libjvm_so, original, builtin_lookup, builtin_sym, tag)
            count_jvm += 1
            continue

        # ----- 3) Registered natives (non-JVM) via source tables -----
        reg_lookup = lookup
        reg_sym = None
        for cand in compat_lookup_candidates:
            reg_sym = registered_method_map.get(cand)
            if reg_sym:
                reg_lookup = cand
                break
        if not reg_sym:
            # Try stripping shaded prefixes (e.g. org.apache.storm.shade.io.netty -> io.netty)
            for _sp in shaded_netty_prefixes:
                if lookup.startswith(_sp + "."):
                    _unshaded = "io.netty." + lookup[len(_sp) + 1:]
                    reg_sym = registered_method_map.get(_unshaded)
                    if reg_sym:
                        reg_lookup = _unshaded
                        break
        if not reg_sym:
            # Netty cross-class alias: epoll.NativeStaticallyReferencedJniMethods declares
            # limit methods (ssizeMax, iovMax, etc.) that are registered under
            # unix.LimitsStaticallyReferencedJniMethods at runtime, and vice versa.
            _epoll_nsrjm = "io.netty.channel.epoll.NativeStaticallyReferencedJniMethods."
            _unix_lsrjm = "io.netty.channel.unix.LimitsStaticallyReferencedJniMethods."
            _unshaded_lookup = lookup
            for _sp in shaded_netty_prefixes:
                if _unshaded_lookup.startswith(_sp + "."):
                    _unshaded_lookup = "io.netty." + _unshaded_lookup[len(_sp) + 1:]
                    break
            if _unshaded_lookup.startswith(_epoll_nsrjm):
                _method = _unshaded_lookup[len(_epoll_nsrjm):]
                reg_sym = registered_method_map.get(_unix_lsrjm + _method)
                if reg_sym:
                    reg_lookup = _unix_lsrjm + _method
            elif _unshaded_lookup.startswith(_unix_lsrjm):
                _method = _unshaded_lookup[len(_unix_lsrjm):]
                reg_sym = registered_method_map.get(_epoll_nsrjm + _method)
                if reg_sym:
                    reg_lookup = _epoll_nsrjm + _method
        if reg_sym:
            owner = resolve_symbol_in_libs(reg_sym, search_libs)
            if owner:
                emit_result(out, owner, original, reg_lookup, reg_sym, "REGISTERED")
            else:
                fence_result = resolve_fence_fallback(reg_lookup, search_libs)
                if fence_result:
                    full_owner, full_sym = fence_result
                    emit_result(
                        out,
                        full_owner,
                        original,
                        reg_lookup,
                        full_sym,
                        "REGISTERED_FENCE_FALLBACK",
                        note=f" (registered as {reg_sym})",
                    )
                    count_registered += 1
                    continue
                out.write(f"{original} -> {reg_sym} [REGISTERED? UNRESOLVED]{alias_tag(original, reg_lookup)}\n")
            count_registered += 1
            continue



        # ----- 4.2) Unsafe local-symbol fallback in libjvm -----
        unsafe_local_sym = UNSAFE_LOCAL_FALLBACKS.get(lookup)
        if unsafe_local_sym:
            owner = resolve_symbol_in_libs(unsafe_local_sym, [libjvm_so] if libjvm_so else search_libs)
            if owner:
                emit_result(out, owner, original, lookup, unsafe_local_sym, "UNSAFE_LOCAL_SYMBOL")
                count_registered += 1
                continue

        # ----- 4.5) Direct libc bridge wrappers (JNA/JFFI-style) -----
        libc_sym = DIRECT_LIBC_METHODS.get(original)
        if libc_sym:
            resolved = try_bridge_resolve(original, libc_sym, "DIRECT_LIBC_BRIDGE", search_libs, out)
            if resolved:
                count_registered += 1
            continue

        # ----- 4.55) Direct JNI bridge wrappers (JDK public->private native indirection) -----
        jni_bridge_sym = DIRECT_JNI_BRIDGES.get(original)
        if jni_bridge_sym:
            resolved = try_bridge_resolve(original, jni_bridge_sym, "DIRECT_JNI_BRIDGE", search_libs, out)
            if resolved:
                count_registered += 1
            continue

        # ----- 4.56) Source-backed JNI wrappers (hidden-symbol fallback) -----
        source_jni_sym = SOURCE_JNI_BRIDGES.get(original)
        if source_jni_sym:
            owner = resolve_symbol_in_libs(source_jni_sym, search_libs)
            if owner:
                emit_result(out, owner, original, original, source_jni_sym, "SOURCE_JNI_BRIDGE")
                count_registered += 1
            elif any(os.path.basename(p) == "libjava.so" for p in search_libs):
                emit_result(out, "libjava.so", original, original, source_jni_sym, "SOURCE_JNI_BRIDGE? SYMBOL_NOT_EXPORTED")
                count_registered += 1
            else:
                out.write(f"{original} -> {source_jni_sym} [SOURCE_JNI_BRIDGE? UNRESOLVED]\n")
            continue

        # ----- 4.6) Sigar gather/list bridge mapping -----
        sigar_sym = SIGAR_LIST_BRIDGES.get(original)
        if sigar_sym:
            # #region agent log
            debug_log("sigar-bridge-entry", "H1", "entered SIGAR list bridge path", {
                "original": original,
                "bridgeSymbol": sigar_sym,
            })
            # #endregion
            resolved = try_bridge_resolve(original, sigar_sym, "SIGAR_LIST_BRIDGE", search_libs, out)
            # #region agent log
            debug_log("sigar-bridge-result", "H1", "SIGAR list bridge resolution result", {
                "original": original,
                "bridgeSymbol": sigar_sym,
                "resolved": resolved,
            })
            # #endregion
            if resolved:
                count_registered += 1
            continue

        # ----- 5) Not found -----
        if original == "org.hyperic.sigar.FileSystem.gather":
            # #region agent log
            debug_log("sigar-not-found", "H3", "FileSystem.gather reached NOT_FOUND_IN_LIBS", {
                "original": original,
                "lookup": lookup,
            })
            # #endregion
        out.write(f"{original}: NOT_FOUND_IN_LIBS\n")
        not_found_count += 1

# ----------------------------
# Post-loop: Apply intrinsic classification to NOT_FOUND methods
# ----------------------------
# Intrinsic is applied AFTER all mapping strategies have been exhausted.
# This ensures methods that can be resolved via RegisterNatives, JNI bridges,
# etc. are mapped to their concrete .so symbols first.
if intrinsic_methods:
    with open(detailed_output_file, "r", encoding="utf-8") as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        if line.rstrip().endswith(": NOT_FOUND_IN_LIBS"):
            method_name = line.split(":")[0].strip()
            lookup_name = UNSAFE_RENAMED.get(method_name, method_name)
            lookup_name = METHOD_ALIASES.get(lookup_name, lookup_name)
            if lookup_name in intrinsic_methods or method_name in intrinsic_methods:
                new_lines.append(f"{method_name} [INTRINSIC]\n")
                count_intrinsic += 1
                not_found_count -= 1
                continue
        new_lines.append(line)
    with open(detailed_output_file, "w", encoding="utf-8") as f:
        f.writelines(new_lines)

# ----------------------------
# Summary
# ----------------------------
total = len(methods)
found_total = total - not_found_count - found_platform

# Two-tier taxonomy by *registration mechanism*:
#   JNI          = static Java_* exports resolved by dlsym (no RegisterNatives needed)
#   JNI_DYNAMIC  = everything wired up at runtime via (*env)->RegisterNatives()
#                  Split inside it is purely by C target-symbol prefix:
#                    JVM_         -> published HotSpot ABI (jvm.h: JVM_StartThread, ...)
#                    Registered_  -> any other C target. This is the union of:
#                                     * the existing "Registered" bucket (Unsafe_*/MHN_*/
#                                       Perf_*/jfr_*/Sigar/libc/JNI bridges, fence fallback,
#                                       UNSAFE_LOCAL_SYMBOL)
#                                     * the existing "JNI Dyn" bucket (JNI_DYNAMIC tags from
#                                       extract_jni_bindings.py: Netty/tcnative/zstd/...)
#                                     * the existing "Netty" bucket (NM-fallback hits)
count_static_jni        = count_jni_direct
count_jni_dyn_jvm       = count_jvm
count_jni_dyn_registered = count_registered + count_jni_dynamic_bindings + count_netty
count_jni_dyn_total     = count_jni_dyn_jvm + count_jni_dyn_registered

print(f"\n=== Classification Summary ===")
print(f"Total methods:        {total}")
print(f"Resolved:             {found_total}  ({100*found_total//total}%)")
print(f"  JNI:                 {count_static_jni}     ")
print(f"    Generic Java_:     {count_static_jni - count_jni_mangled}")
print(f"    Partial (_1/$/__): {count_jni_mangled}")
print(f"  JNI_DYNAMIC:         {count_jni_dyn_total}     ")
print(f"    JVM_:              {count_jni_dyn_jvm}     (target symbol starts with JVM_)")
print(f"    Registered_:       {count_jni_dyn_registered}     (Registered_libjvm + JFR + Netty)")
print(f"  Intrinsic (JIT):     {count_intrinsic}")
print(f"Platform-excluded:    {found_platform}")
print(f"NOT_FOUND_IN_LIBS:    {not_found_count}")
print(f"\nOutput: {detailed_output_file}")
