#!/usr/bin/env python3
# format_jni_by_lib.py (robust)
import sys, argparse, re, os
from collections import OrderedDict

# Determine output directory based on IMG_NAME or OUTPUTS_DIR environment variable
img_name = os.environ.get("IMG_NAME", "").strip()
outputs_dir_env = os.environ.get("OUTPUTS_DIR", "").strip()

if outputs_dir_env:
    SPLIT_DIR_DEFAULT = outputs_dir_env
elif img_name:
    SPLIT_DIR_DEFAULT = f"outputs_{img_name}"
else:
    SPLIT_DIR_DEFAULT = "outputs"

FINAL_OUT_DEFAULT = "final.txt"

env_lib_dirs = os.environ.get("LIB_DIRS")
if env_lib_dirs:
    LIB_DIRS = [p for p in env_lib_dirs.split(os.pathsep) if p]
else:
    # No hardcoded paths - rely on environment variables
    LIB_DIRS = []

def parse_lines(lines, debug=False, max_debug=20):
    """
    Parse lines like:
      libname.so:java.lang.Class.forName0 -> Java_java_lang_Class_forName0 [JNI]
    and group by 'libname.so'.
    """
    groups = OrderedDict()
    skipped = 0
    shown = 0

    # First split lib vs the rest (robust against extra spaces/tabs)
    split_re = re.compile(r'^\s*([^:]+)\s*:\s*(.+?)\s*$')
    # Then find the jni function name after '->'
    jni_re = re.compile(r'->\s*([A-Za-z0-9_]+)')

    for raw in lines:
        line = raw.rstrip("\r\n")
        if not line.strip():
            continue

        m = split_re.match(line)
        if not m:
            if debug and shown < max_debug:
                print(f"[DEBUG] skip (no lib:rest): {line!r}", file=sys.stderr)
                shown += 1
            skipped += 1
            continue

        lib, rest = m.group(1).strip(), m.group(2).strip()

        # Optionally strip trailing "[JNI]" or similar annotations
        # We primarily rely on the '-> symbol' capture below.
        jm = jni_re.search(rest)
        if not jm:
            if debug and shown < max_debug:
                print(f"[DEBUG] skip (no '-> symbol'): {line!r}", file=sys.stderr)
                shown += 1
            skipped += 1
            continue

        jni = jm.group(1).strip()
        groups.setdefault(lib, []).append(jni)

    if debug:
        print(f"[DEBUG] parsed groups={len(groups)}, skipped_lines={skipped}", file=sys.stderr)
    return groups

def normalize_methods(methods, do_sort=False, do_uniq=False):
    if do_uniq:
        seen = set()
        methods = [m for m in methods if (m not in seen and not seen.add(m))]
    if do_sort:
        methods = sorted(methods, key=str)
    return methods

def write_combined(groups, final_out, do_sort=False, do_uniq=False):
    lines = []
    first = True
    for lib, methods in groups.items():
        methods = normalize_methods(methods, do_sort, do_uniq)
        if not methods:
            continue
        if not first:
            lines.append("")
        lines.append(f"{lib}:")
        lines.extend(methods)
        first = False
    with open(final_out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + ("\n" if lines else ""))

def lib_relative_path(name: str) -> str:
    """Convert a library path to a relative path suitable for per-library output files.

    Strips the leading LIBS_<IMG_NAME>/ prefix so that the output filename preserves
    the subdirectory structure (e.g. JDK8_LIBS/amd64/libnet.so).  This allows
    automate_syscall_analysis.sh to locate the actual binary at
    $BINARY_DIR/JDK8_LIBS/amd64/libnet.so.

    Examples:
        LIBS_tomcat_7.0/JDK8_LIBS/amd64/libnet.so  ->  JDK8_LIBS/amd64/libnet.so
        LIBS_cassandra_3.0.29/libjvm.so             ->  libjvm.so
        libc.so.6                                   ->  libc.so.6
    """
    # Strip leading LIBS_<anything>/ prefix (one path component)
    m = re.match(r'^LIBS_[^/]+/(.+)$', name)
    if m:
        return m.group(1)
    return name

def safe_filename(name: str) -> str:
    """Sanitise a single path component (no slashes expected)."""
    return re.sub(r'[^A-Za-z0-9._-]+', '_', name).strip('_')

def write_per_library(groups, split_dir, do_sort=False, do_uniq=False):
    os.makedirs(split_dir, exist_ok=True)
    for lib, methods in groups.items():
        methods = normalize_methods(methods, do_sort, do_uniq)
        if not methods:
            continue
        rel = lib_relative_path(lib)
        # Preserve subdirectory structure (e.g. JDK8_LIBS/amd64/)
        out_path = os.path.join(split_dir, rel + ".txt")
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write("\n".join(methods) + "\n")

def main():
    ap = argparse.ArgumentParser(description="Group JNI methods by library and write combined + per-library outputs.")
    ap.add_argument("file", nargs="?", help="Input file (default: stdin)")
    ap.add_argument("--libs", nargs="*", default=None, help="Only include these library names (exact match).")
    ap.add_argument("--lib-dirs", nargs="*", default=None, help="Library directories to search (overrides LIB_DIRS env var)")
    ap.add_argument("--show-lib-dirs", action="store_true", help="Show configured library directories and exit")
    ap.add_argument("--sort", action="store_true", help="Sort method names within each library.")
    ap.add_argument("--uniq", action="store_true", help="Deduplicate method names (keep first occurrence).")
    ap.add_argument("--final-out", default=FINAL_OUT_DEFAULT, help=f"Path for combined output (default: {FINAL_OUT_DEFAULT})")
    ap.add_argument("--split-dir", default=SPLIT_DIR_DEFAULT, help=f"Directory for per-library files (default: {SPLIT_DIR_DEFAULT})")
    ap.add_argument("--debug", action="store_true", help="Print reasons for skipped lines to stderr")
    args = ap.parse_args()

    # Override LIB_DIRS if --lib-dirs is provided (kept for future use)
    if args.lib_dirs:
        global LIB_DIRS
        LIB_DIRS = args.lib_dirs

    if args.show_lib_dirs:
        print("Configured library directories:")
        for i, lib_dir in enumerate(LIB_DIRS, 1):
            print(f"  {i}. {lib_dir}")
        return

    data = sys.stdin.read() if args.file is None else open(args.file, "r", encoding="utf-8", errors="replace").read()
    groups = parse_lines(data.splitlines(), debug=args.debug)

    if args.libs:
        # Warn if filters exclude everything
        before = len(groups)
        groups = OrderedDict((lib, groups[lib]) for lib in groups if lib in args.libs)
        if args.debug and not groups:
            print(f"[DEBUG] --libs filtered out all groups. Available libs were: {list(groups.keys())}", file=sys.stderr)

    write_combined(groups, args.final_out, do_sort=args.sort, do_uniq=args.uniq)
    write_per_library(groups, args.split_dir, do_sort=args.sort, do_uniq=args.uniq)

    total_methods = sum(len(v) for v in groups.values())
    print(f"Wrote combined: {args.final_out}  (libs={len(groups)}, methods={total_methods})")
    print(f"Wrote per-library files to: {args.split_dir}")

if __name__ == "__main__":
    main()
