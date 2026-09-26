#!/usr/bin/env python3
"""
extract_jni_bindings.py

Statically extract JNINativeMethod[] tables from .so files to recover the
Java-to-C bindings that are registered at runtime via
    (*env)->RegisterNatives(env, cls, method_table, count);

This is the canonical extractor for *third-party* JNI (Netty transport-native,
Hadoop, etc.): static registration tables linked into RELRO.  For OpenJDK
HotSpot class/ JVM_* tables in C++ sources, use extract_jvm_native_tables.py
instead — it does not read arbitrary vendor .so files.

Algorithm per .so (see JNI_DYNAMIC_EXTRACTOR_PLAN for full design):
  1. Qualify   - lib must export JNI_OnLoad and match host arch.
  2. Locate    - enumerate R_*_RELATIVE relocations targeting any RELRO bundle
                 (.data.rel.ro, .data.rel.ro.local, ...) and group
                 them by stride 24 (3 pointers x 8 bytes on LP64).
  3. Validate  - each triple (p_name, p_sig, p_fn) must resolve to
                   name : valid Java identifier string in a readable section,
                   sig  : valid JNI signature '(...)X' in a readable section,
                   fn   : address inside .text resolvable to a symbol.
  4. Derive    - infer Java class FQN from the C symbol prefix using a set of
                 well-known tcnative / netty / static-JNI naming rules.
                 Confidence is HIGH_CONF when verified against a matching JNI
                 class path string present in .rodata; otherwise SYM_INFER.
  5. Emit      - one binding per line:
                   <lib>|<JavaFQN>|<signature>|<C_symbol>|<confidence>

Output files (in --output-dir, default: same as --libs-dir):
  jni_dynamic_bindings.txt   main result
  jni_dynamic_summary.txt    per-lib counts and skipped libs

Non-goals (documented, not implemented here):
  - Non-PIC / fully-relocated .so files (no R_*_RELATIVE relocs).
  - JNINativeMethod[] arrays constructed at runtime rather than in rodata/data.
  - Disassembly-based verification of RegisterNatives call sites.
"""

from __future__ import annotations

import argparse
import bisect
import os
import re
import sys
import platform
from dataclasses import dataclass
from typing import Iterable, Optional

try:
    from elftools.elf.elffile import ELFFile
    from elftools.elf.sections import SymbolTableSection
    from elftools.common.exceptions import ELFError
except ImportError:
    sys.stderr.write(
        "ERROR: pyelftools is required. Install with:\n"
        "  pip install pyelftools\n"
    )
    sys.exit(2)


# ---------------------------------------------------------------------------
# Architecture -> ELF R_*_RELATIVE reloc type code.
# pyelftools exposes these as ints via ENUM_RELOC_TYPE_<arch>, but we hardcode
# the small set we care about to avoid per-arch enum imports.
# ---------------------------------------------------------------------------
R_RELATIVE_BY_ARCH = {
    "x64":     8,    # R_X86_64_RELATIVE
    "x86":     8,    # R_386_RELATIVE
    "AArch64": 1027, # R_AARCH64_RELATIVE
    "ARM":     23,   # R_ARM_RELATIVE
}

# Filename markers used to skip foreign-arch libraries during scan.
FOREIGN_ARCH_MARKERS = {
    "x86_64":  ("aarch_64", "aarch64", "arm_", "_arm.", "ppc", "s390x", "riscv"),
    "aarch64": ("x86_64", "_x86.", "ppc", "s390x", "riscv"),
}

POINTER_SIZE = 8  # LP64; adjust if we ever support 32-bit ELF.
TRIPLE_STRIDE = 3 * POINTER_SIZE


# ---------------------------------------------------------------------------
# Regexes for validating extracted triples.
# ---------------------------------------------------------------------------
JAVA_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")
# JNI method signature: (<param-types>)<return-type>
# Types: primitive letters V Z B C S I F D J, object L<path>;, array [ prefix
JNI_SIG_RE = re.compile(r"^\(([VZBCSIFDJ]|L[\w/$]+;|\[+(?:[VZBCSIFDJ]|L[\w/$]+;))*\)"
                        r"([VZBCSIFDJ]|L[\w/$]+;|\[+(?:[VZBCSIFDJ]|L[\w/$]+;))$")


# ---------------------------------------------------------------------------
# Class-name inference rules. Each rule is (regex, transform_fn).
# transform_fn takes the Match and returns the Java FQN (with dots).
#
# Order matters: more specific rules first.
# ---------------------------------------------------------------------------
_CLASS_RULES: list[tuple[re.Pattern, "callable"]] = [
    # 1. netty tcnative: netty_internal_tcnative_<Class>_<method>
    (re.compile(r"^netty_internal_tcnative_([A-Za-z][A-Za-z0-9]*)_\w+$"),
     lambda m: f"io.netty.internal.tcnative.{m.group(1)}"),

    # 2a. netty channel.unix errno/static JNI helpers — RegisterNatives targets
    # ErrorsStaticallyReferencedJniMethods only (transport-native-unix-common
    # netty_unix_errors.c ERRORS_CLASSNAME). Symbols: netty_unix_errors_errnoEPIPE.
    # Must precede generic netty_unix_* (else "errors" is mis-read as class Errors).
    (re.compile(r"^netty_unix_errors_\w+$"),
     lambda m: "io.netty.channel.unix.ErrorsStaticallyReferencedJniMethods"),

    # 2. netty channel.unix: netty_unix_<classStem>_<method>  (classStem is
    #    lowercase run e.g. buffer, filedescriptor, linuxsocket — method is camelCase)
    #    Greedy [a-z]+ avoids ambiguous non-greedy splits on multi-token stems.
    (re.compile(r"^netty_unix_([a-z]+)_([a-zA-Z][a-zA-Z0-9]*)$"),
     lambda m: f"io.netty.channel.unix.{_title_snake(m.group(1))}"),

    # 3. netty channel.epoll: netty_epoll_<classStem>_<method>
    (re.compile(r"^netty_epoll_([a-z]+)_([a-zA-Z][a-zA-Z0-9]*)$"),
     lambda m: f"io.netty.channel.epoll.{_title_snake(m.group(1))}"),

    # 4. netty channel.kqueue
    (re.compile(r"^netty_kqueue_([a-z]+)_([a-zA-Z][a-zA-Z0-9]*)$"),
     lambda m: f"io.netty.channel.kqueue.{_title_snake(m.group(1))}"),

    # 5. Static JNI mangle: Java_<pkg_underscored>_<Class>_<method>
    # We can't perfectly demangle without knowing where pkg ends and class
    # begins, so fall back on best-effort: treat last underscored token as
    # the method and the one before as the class.
    (re.compile(r"^Java_(.+)_([A-Za-z][A-Za-z0-9]*)_\w+$"),
     lambda m: _java_mangle_to_fqn(m.group(1), m.group(2))),
]


_NETTY_EPOLL_NATIVE_SYM_RE = re.compile(r"^netty_epoll_native_(\w+)$")

# Methods registered via statically_referenced_fixed_method_table in netty_epoll_native.c share the
# netty_epoll_native_<method> prefix with Native.fixed_method_table — classify using JNI method names.
_NETTY_EPOLL_NATIVE_STATIC_REF_METHODS = frozenset({
    "epollet", "epollin", "epollout", "epollrdhup", "epollerr",
    "ssizeMax", "tcpMd5SigMaxKeyLen", "iovMax", "uioMaxIov",
    "isSupportingSendmmsg", "isSupportingRecvmmsg",
    "tcpFastopenMode", "kernelVersion",
})


# Known trailing segments on Netty class stems collapsed into one lowercase token
# in native symbols (e.g. netty_epoll_linuxsocket_*).
_NETTY_COMPOUND_SUFFIXES = (
    "socket",
    "descriptor",
    "buffer",
    "address",
    "channel",
    "factory",
    "iterator",
    "credentials",
    "methods",
)


def _title_snake(s: str) -> str:
    """`file_descriptor` -> `FileDescriptor`; `linuxsocket` -> `LinuxSocket`.

    Netty epoll/unix symbols omit underscores inside class stems; without splitting,
    Python's str.capitalize() yields `Linuxsocket` instead of `LinuxSocket`.
    """
    if "_" in s:
        return "".join(p.capitalize() for p in s.split("_"))
    sl = s.lower()
    for suf in sorted(_NETTY_COMPOUND_SUFFIXES, key=len, reverse=True):
        if sl.endswith(suf) and len(sl) > len(suf):
            pref = sl[: -len(suf)]
            if 2 <= len(pref) <= 18 and pref.isalpha():
                return pref.capitalize() + suf.capitalize()
    return s.capitalize()


def _java_mangle_to_fqn(pkg_underscored: str, class_name: str) -> str:
    """Convert `com_example_pkg` + `MyClass` -> `com.example.pkg.MyClass`.
    JNI mangling rule: / -> _, _ -> _1, ; -> _2, [ -> _3. We only handle the
    common / -> _ case; the _1/_2/_3 escapes are rare in practice and marked
    as lower-confidence."""
    pkg_dotted = pkg_underscored.replace("_", ".")
    return f"{pkg_dotted}.{class_name}"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Binding:
    lib: str
    java_fqn: str
    signature: str
    c_symbol: str
    confidence: str  # HIGH_CONF | SYM_INFER | UNKNOWN


@dataclass
class LibResult:
    lib: str
    status: str                # OK | SKIPPED_NO_JNI_ONLOAD | SKIPPED_FOREIGN_ARCH | SKIPPED_NOT_ELF | ERROR
    bindings: list[Binding]
    message: str = ""


# ---------------------------------------------------------------------------
# Core extraction
# ---------------------------------------------------------------------------
def _section_containing(sections_by_range: list, addr: int):
    """sections_by_range is a sorted list of (start, end, section)."""
    for start, end, sec in sections_by_range:
        if start <= addr < end:
            return sec
    return None


def _read_cstring(sec, addr: int) -> Optional[str]:
    data = sec.data()
    off = addr - sec["sh_addr"]
    if off < 0 or off >= len(data):
        return None
    end = data.find(b"\x00", off)
    if end == -1 or end == off:
        return None
    try:
        return data[off:end].decode("utf-8")
    except UnicodeDecodeError:
        return None


def _build_symbol_map(elf) -> dict[int, str]:
    """Map address -> symbol name for anything that looks like a function.
    Prefers .symtab (local+global) but falls back to .dynsym alone when the
    binary is stripped."""
    symbol_map: dict[int, str] = {}
    for section_name in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(section_name)
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            if not sym.name:
                continue
            if sym["st_info"]["type"] in ("STT_FUNC", "STT_NOTYPE"):
                # Prefer named symbols; don't overwrite a real name with an empty string.
                symbol_map.setdefault(sym["st_value"], sym.name)
    return symbol_map


def _relro_address_intervals(elf) -> list[tuple[int, int]]:
    """All RELRO pages holding const relocatables — not only `.data.rel.ro`.

    Linkers often place `static const JNINativeMethod …[]` in `.data.rel.ro.local`
    or other `.data.rel.ro*` sections; R_*_RELATIVE relocs still target those VMAs.
    """
    intervals: list[tuple[int, int]] = []
    for s in elf.iter_sections():
        name = s.name or ""
        if not name.startswith(".data.rel.ro"):
            continue
        addr = s["sh_addr"]
        sz = s["sh_size"]
        if addr > 0 and sz > 0:
            intervals.append((addr, addr + sz))
    intervals.sort(key=lambda t: t[0])
    merged: list[tuple[int, int]] = []
    for lo, hi in intervals:
        if not merged or lo > merged[-1][1]:
            merged.append((lo, hi))
        else:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
    return merged


def _reloc_offset_in_relro(off: int, intervals: list[tuple[int, int]]) -> bool:
    for lo, hi in intervals:
        if lo <= off < hi:
            return True
    return False


def _build_sorted_fn_rows(elf) -> tuple[list[int], list[tuple[int, int, str]]]:
    """Sorted unique symbols (STT_FUNC/STT_NOTYPE) for floor lookup of fn pointers."""
    rows: list[tuple[int, int, str]] = []
    seen_addr: set[int] = set()
    for section_name in (".symtab", ".dynsym"):
        sec = elf.get_section_by_name(section_name)
        if not isinstance(sec, SymbolTableSection):
            continue
        for sym in sec.iter_symbols():
            if not sym.name:
                continue
            typ = sym["st_info"]["type"]
            if typ not in ("STT_FUNC", "STT_NOTYPE"):
                continue
            val = sym["st_value"]
            if val == 0:
                continue
            sz = sym["st_size"]
            if val in seen_addr:
                continue
            seen_addr.add(val)
            rows.append((val, sz, sym.name))
    rows.sort(key=lambda t: t[0])
    keys = [r[0] for r in rows]
    return keys, rows


def _c_symbol_for_fn_addr(
    fn_addr: int,
    symbol_map: dict[int, str],
    sorted_keys: list[int],
    sorted_rows: list[tuple[int, int, str]],
) -> Optional[str]:
    """Resolve a text-pointer from JNINativeMethod.fnPtr to a demanglable name.

    RELATIVE relocs usually point at the exact symbol start, but thunks, section
    padding, or linker quirks can land a few bytes in — use a containing FUNC.
    """
    sym = symbol_map.get(fn_addr)
    if sym is not None:
        return sym
    if not sorted_keys:
        return None
    i = bisect.bisect_right(sorted_keys, fn_addr) - 1
    if i < 0:
        return None
    val, sz, name = sorted_rows[i]
    if sz > 0 and fn_addr >= val + sz:
        return None
    return name


def _classify_symbol(c_symbol: str, jni_method_name: str = "") -> tuple[Optional[str], str]:
    """Return (class_fqn, confidence_tier). Tier is HIGH_CONF candidate when
    a rule fires; final HIGH_CONF requires string verification later.

    jni_method_name is the RegisterNatives JNINativeMethod name — splits netty_epoll_native_*
    between Native and NativeStaticallyReferencedJniMethods."""
    if _NETTY_EPOLL_NATIVE_SYM_RE.match(c_symbol) and jni_method_name:
        if jni_method_name in _NETTY_EPOLL_NATIVE_STATIC_REF_METHODS:
            return "io.netty.channel.epoll.NativeStaticallyReferencedJniMethods", "SYM_INFER"
        return "io.netty.channel.epoll.Native", "SYM_INFER"

    for pattern, transform in _CLASS_RULES:
        m = pattern.match(c_symbol)
        if m:
            return transform(m), "SYM_INFER"
    return None, "UNKNOWN"


def _lib_is_foreign_arch(path: str, host_arch: str) -> bool:
    base = os.path.basename(path).lower()
    markers = FOREIGN_ARCH_MARKERS.get(host_arch, ())
    return any(m in base for m in markers)


def process_so(path: str, host_arch: str) -> LibResult:
    """Extract JNINativeMethod[] bindings from a single .so file."""
    if _lib_is_foreign_arch(path, host_arch):
        return LibResult(path, "SKIPPED_FOREIGN_ARCH", [])

    try:
        f = open(path, "rb")
    except OSError as e:
        return LibResult(path, "ERROR", [], f"open failed: {e}")

    try:
        try:
            elf = ELFFile(f)
        except Exception as e:
            return LibResult(path, "SKIPPED_NOT_ELF", [], f"not ELF: {e}")

        try:
            return _process_elf(path, elf)
        except ELFError as e:
            return LibResult(path, "ERROR", [], f"ELF error: {e}")
    finally:
        f.close()


def _process_elf(path: str, elf) -> LibResult:
    """Main processing body, split out so that all ELFError instances raised
    anywhere inside can be caught by the caller."""
    arch = elf.get_machine_arch()
    reloc_type = R_RELATIVE_BY_ARCH.get(arch)
    if reloc_type is None:
        return LibResult(path, "SKIPPED_NOT_ELF", [], f"unsupported arch: {arch}")

    # Qualify: must export JNI_OnLoad
    dynsym = elf.get_section_by_name(".dynsym")
    has_onload = False
    if isinstance(dynsym, SymbolTableSection):
        for sym in dynsym.iter_symbols():
            if sym.name == "JNI_OnLoad":
                has_onload = True
                break
    if not has_onload:
        return LibResult(path, "SKIPPED_NO_JNI_ONLOAD", [])

    # Build section range table
    sections_by_range = []
    for s in elf.iter_sections():
        sz = s["sh_size"]
        addr = s["sh_addr"]
        if sz > 0 and addr > 0:
            sections_by_range.append((addr, addr + sz, s))
    sections_by_range.sort(key=lambda t: t[0])

    relro_ivs = _relro_address_intervals(elf)
    if not relro_ivs:
        return LibResult(path, "OK", [],
                         "no .data.rel.ro* (non-PIC or unusual layout)")

    # Collect R_*_RELATIVE relocs targeting any RELRO bundle
    rela = elf.get_section_by_name(".rela.dyn")
    if rela is None:
        return LibResult(path, "OK", [], "no .rela.dyn")

    relocs: list[tuple[int, int]] = []  # (offset, addend)
    for r in rela.iter_relocations():
        if r["r_info_type"] != reloc_type:
            continue
        off = r["r_offset"]
        if _reloc_offset_in_relro(off, relro_ivs):
            relocs.append((off, r["r_addend"]))
    relocs.sort()

    # Group into stride-24 triples (consecutive 3 pointers at offsets N, N+8, N+16).
    # Do NOT enforce 24-byte alignment from section start — JNINativeMethod arrays
    # can start at any offset depending on linker layout.
    triples: list[tuple[tuple[int, int], tuple[int, int], tuple[int, int]]] = []
    i = 0
    while i + 2 < len(relocs):
        o0, o1, o2 = relocs[i][0], relocs[i + 1][0], relocs[i + 2][0]
        if o1 == o0 + POINTER_SIZE and o2 == o0 + 2 * POINTER_SIZE:
            triples.append((relocs[i], relocs[i + 1], relocs[i + 2]))
            i += 3
        else:
            i += 1

    symbol_map = _build_symbol_map(elf)
    sorted_fn_keys, sorted_fn_rows = _build_sorted_fn_rows(elf)
    rodata = elf.get_section_by_name(".rodata")
    rodata_blob = rodata.data() if rodata is not None else b""

    bindings: list[Binding] = []
    seen: set[tuple[str, str, str]] = set()

    for t in triples:
        name_addr = t[0][1]
        sig_addr = t[1][1]
        fn_addr = t[2][1]

        name_sec = _section_containing(sections_by_range, name_addr)
        sig_sec = _section_containing(sections_by_range, sig_addr)
        if name_sec is None or sig_sec is None:
            continue

        name = _read_cstring(name_sec, name_addr)
        sig = _read_cstring(sig_sec, sig_addr)
        if not name or not sig:
            continue
        if not JAVA_IDENT_RE.match(name):
            continue
        if not JNI_SIG_RE.match(sig):
            continue

        c_symbol = symbol_map.get(fn_addr)
        if not c_symbol:
            continue

        class_fqn, tier = _classify_symbol(c_symbol, name)
        if class_fqn is None:
            java_fqn = f"UNKNOWN.{name}"
            confidence = "UNKNOWN"
        else:
            java_fqn = f"{class_fqn}.{name}"
            # Verify against rodata JNI class path string
            probe = class_fqn.replace(".", "/").encode("utf-8")
            confidence = "HIGH_CONF" if probe in rodata_blob else tier

        key = (java_fqn, sig, c_symbol)
        if key in seen:
            continue
        seen.add(key)
        bindings.append(Binding(
            lib=os.path.basename(path),
            java_fqn=java_fqn,
            signature=sig,
            c_symbol=c_symbol,
            confidence=confidence,
        ))

    return LibResult(path, "OK", bindings)


# ---------------------------------------------------------------------------
# CLI + I/O
# ---------------------------------------------------------------------------
def detect_host_arch() -> str:
    m = platform.machine().lower()
    if m in ("x86_64", "amd64"):
        return "x86_64"
    if m in ("aarch64", "arm64"):
        return "aarch64"
    return m


def iter_so_files(libs_dir: str) -> Iterable[str]:
    for root, _dirs, files in os.walk(libs_dir):
        for name in files:
            # Match common shared-object filename patterns.
            if name.endswith(".so") or ".so." in name:
                yield os.path.join(root, name)


def write_outputs(results: list[LibResult], output_dir: str):
    os.makedirs(output_dir, exist_ok=True)
    bindings_path = os.path.join(output_dir, "jni_dynamic_bindings.txt")
    summary_path = os.path.join(output_dir, "jni_dynamic_summary.txt")

    with open(bindings_path, "w", encoding="utf-8") as out:
        for r in results:
            for b in r.bindings:
                out.write(f"{b.lib}|{b.java_fqn}|{b.signature}|{b.c_symbol}|{b.confidence}\n")

    with open(summary_path, "w", encoding="utf-8") as out:
        out.write("# lib | status | bindings | high_conf | sym_infer | unknown | note\n")
        for r in sorted(results, key=lambda x: x.lib):
            hc = sum(1 for b in r.bindings if b.confidence == "HIGH_CONF")
            si = sum(1 for b in r.bindings if b.confidence == "SYM_INFER")
            un = sum(1 for b in r.bindings if b.confidence == "UNKNOWN")
            out.write(f"{os.path.basename(r.lib)}|{r.status}|{len(r.bindings)}"
                      f"|{hc}|{si}|{un}|{r.message}\n")

    return bindings_path, summary_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[1] if __doc__ else "")
    parser.add_argument(
        "--libs-dir",
        default=os.environ.get("LIBS_DIR"),
        metavar="LIBS_DIR",
        help="Directory containing .so files to scan "
             "(default: LIBS_DIR env if set).",
    )
    parser.add_argument(
        "--output-dir",
        default=os.environ.get("OUTPUT_DIR"),
        metavar="OUTPUT_DIR",
        help="Directory to write jni_dynamic_bindings.txt and summary "
             "(default: OUTPUT_DIR env, else same as --libs-dir).",
    )
    parser.add_argument("--host-arch", default=None,
                        help="Host architecture for foreign-arch filtering "
                             "(default: auto-detect).")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Log per-lib progress to stderr.")
    args = parser.parse_args(argv)

    if not args.libs_dir:
        parser.error("--libs-dir is required (set LIBS_DIR or pass --libs-dir DIR)")

    if not os.path.isdir(args.libs_dir):
        sys.stderr.write(f"ERROR: libs-dir not found: {args.libs_dir}\n")
        return 1

    output_dir = args.output_dir or args.libs_dir

    host_arch = args.host_arch or detect_host_arch()

    results: list[LibResult] = []
    for so in iter_so_files(args.libs_dir):
        r = process_so(so, host_arch)
        results.append(r)
        if args.verbose:
            sys.stderr.write(f"  {r.status:25s} {len(r.bindings):5d} bindings  "
                             f"{os.path.basename(so)}\n")

    bindings_path, summary_path = write_outputs(results, output_dir)

    total = sum(len(r.bindings) for r in results)
    processed = sum(1 for r in results if r.status == "OK")
    print(f"Scanned {len(results)} .so files (host_arch={host_arch})")
    print(f"  processed:  {processed}")
    print(f"  bindings:   {total}")
    print(f"  output:     {bindings_path}")
    print(f"  summary:    {summary_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

