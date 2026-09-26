#!/usr/bin/env python3
"""
Run SysPart over the native symbols bound through JNA, jnr-ffi and Panama FFM.

The bytecode detectors find these bindings, but the mapper only consumes
native_methods.txt -- the plain `native`-keyword scan -- so the symbols they
resolve never reach binary analysis. Tomcat's FFM OpenSSL layer binds 207
distinct symbols in libssl and libcrypto; none of them were seeded as SysPart
entry points, so no syscall reachable only through that path appeared in the
generated profile.

Unlike JNI, these bindings carry the library and symbol name explicitly:

    ffi | <org.apache...openssl_h: int SSL_CONF_cmd(...)> | ssl | SSL_CONF_cmd | downcallHandle | ...
          detector       caller signature                  lib   symbol

so each row is already a (library, entry point) pair. This groups them by
library, resolves each library name against the container mirror, and runs
SysPart with those symbols as start functions.

Output goes to jna_ffi_analysis/union_syscalls.txt, which merge_all_syscalls.py
STEP 4 already reads.

Usage:
  IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 ./scripts/analyse_jna_ffi.py --run-syspart
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path

SONAME_RE = re.compile(r"soname *: *\[(.+?)\]")
PRUNED_DIRS = {".git", ".github", "doc", "docs", "test", "tests", "examples"}

# Library names the detectors emit when the load site could not be resolved.
UNRESOLVED_LIBS = {"<?>", "<unknown>", ""}
# Native.load(null, ...) and Native.load(Class) bind against the C library.
DEFAULT_C_LIB_MARKERS = {"<null:default-c-lib>", "<default>"}


def run_text(cmd, timeout=30, env=None, cwd=None):
    try:
        proc = subprocess.run(
            cmd, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, env=env, cwd=str(cwd) if cwd else None,
        )
        return proc.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return ""


def normalize_key(value):
    """libssl.so.1.1.1zh -> ssl, matching NativeLibraryNames.normalizeKey."""
    key = value.strip().lower()
    if key.startswith("lib"):
        key = key[3:]
    for suffix in (".so", ".dylib", ".dll"):
        idx = key.find(suffix)
        if idx > 0:
            key = key[:idx]
            break
    return key


def build_lib_index(libs_dir):
    """Maps normalized library names to files in the mirror."""
    index = {}
    for current, dirs, files in os.walk(libs_dir):
        dirs[:] = [d for d in dirs if d not in PRUNED_DIRS]
        for name in files:
            if ".so" not in name:
                continue
            path = Path(current) / name
            if path.is_symlink():
                continue
            for key in {normalize_key(name)}:
                index.setdefault(key, path)
            soname = SONAME_RE.search(run_text(["readelf", "-d", str(path)], timeout=5))
            if soname:
                index.setdefault(normalize_key(soname.group(1)), path)
    return index


def parse_hits(paths):
    """
    Collects (library, symbol) pairs from the merged detector reports.

    Every detector writes `... | lib | symbol | ...`, and the merged files
    prefix each row with the detector name, so lib/symbol sit at a fixed
    offset regardless of which detector produced the row.
    """
    by_lib = {}
    skipped = {}
    seen_rows = set()

    for path in paths:
        if not path.is_file():
            continue
        for raw in path.read_text(errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("===") or line.startswith("Format:"):
                continue
            parts = [p.strip() for p in line.split("|")]
            if len(parts) < 4:
                continue
            detector, lib, symbol = parts[0], parts[2], parts[3]
            if not symbol or symbol in UNRESOLVED_LIBS:
                continue
            # A symbol is a C identifier; anything else is a parse artifact.
            if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol):
                continue
            if lib in DEFAULT_C_LIB_MARKERS:
                lib = "c"
            if lib in UNRESOLVED_LIBS:
                skipped.setdefault(detector, set()).add(symbol)
                continue
            # Conditional names are recorded joined ("msvcrt|c"); the split on
            # "|" above already separated them, so re-splitting is unnecessary.
            key = (lib, symbol)
            if key in seen_rows:
                continue
            seen_rows.add(key)
            by_lib.setdefault(lib, set()).add(symbol)

    return by_lib, skipped


def build_user_library_path(libs_dir):
    paths = [str(libs_dir)]
    for sub in sorted(p for p in libs_dir.rglob("*") if p.is_dir()):
        paths.append(str(sub))
    return ":".join(paths)


def run_syspart(syspart_dir, binary, out_dir, startfunc_file, user_library_path):
    app_dir = syspart_dir / "analysis" / "app"
    compute = app_dir / "src" / "scripts" / "compute_syscalls.sh"
    out_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["USER_LIBRARY_PATH"] = user_library_path
    with (out_dir / "logfile.txt").open("ab") as log:
        proc = subprocess.run(
            [str(compute), str(binary), str(out_dir), str(startfunc_file), "--log"],
            cwd=str(app_dir), env=env, stdout=log, stderr=subprocess.STDOUT, check=False,
        )
    return proc.returncode


def main():
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--img-name", default=os.environ.get("IMG_NAME"))
    parser.add_argument("--project-root", default=None)
    parser.add_argument("--libs-dir", default=None)
    parser.add_argument("--outputs-dir", default=None,
                        help="Directory holding the detector reports")
    parser.add_argument("--syspart-dir", default=None)
    parser.add_argument("--run-syspart", action="store_true",
                        help="Run SysPart; without it only start-function files are written")
    parser.add_argument("--force", action="store_true", help="Recompute existing results")
    args = parser.parse_args()

    if not args.img_name:
        parser.error("IMG_NAME is required (pass --img-name or set $IMG_NAME)")

    img = args.img_name
    root = Path(args.project_root).resolve() if args.project_root \
        else Path(__file__).resolve().parent.parent
    libs_dir = Path(args.libs_dir).resolve() if args.libs_dir else root / f"LIBS_{img}"
    outputs_dir = Path(args.outputs_dir).resolve() if args.outputs_dir \
        else root / f"outputs_{img}"
    syspart_dir = Path(args.syspart_dir).resolve() if args.syspart_dir else root / "SysPartCode"
    work = root / "jna_ffi_analysis"
    startfunc_root = work / "startfuncs"
    syscalls_root = work / "syscalls"

    print("=" * 60)
    print(" JNA / jnr-ffi / FFM binary analysis")
    print("=" * 60)
    print(f"IMG_NAME: {img}")
    print(f"LIBS:     {libs_dir}")
    print(f"reports:  {outputs_dir}")

    if not libs_dir.is_dir():
        print(f"ERROR: LIBS directory not found: {libs_dir}", file=sys.stderr)
        return 1

    hit_files = [outputs_dir / "jna_hits.txt", outputs_dir / "ffi_all_hits.txt"]
    present = [p for p in hit_files if p.is_file()]
    if not present:
        print(f"\nERROR: no detector reports found in {outputs_dir}", file=sys.stderr)
        print("       Run the bytecode analysis (JNADetector) first.", file=sys.stderr)
        return 1

    by_lib, skipped = parse_hits(present)
    total_symbols = sum(len(s) for s in by_lib.values())
    print(f"\nBindings: {total_symbols} symbols across {len(by_lib)} librar"
          f"{'y' if len(by_lib) == 1 else 'ies'}")
    for lib in sorted(by_lib):
        print(f"  {lib:<24} {len(by_lib[lib])} symbols")
    if skipped:
        n = sum(len(s) for s in skipped.values())
        print(f"\n{n} symbol(s) had an unresolved library and cannot be analysed:")
        for detector in sorted(skipped):
            print(f"  {detector}: {len(skipped[detector])}")

    if not by_lib:
        print("\nNothing to analyse.")
        return 0

    print("\nResolving libraries against the mirror...")
    index = build_lib_index(libs_dir)
    user_library_path = build_user_library_path(libs_dir)

    resolved, unresolved = {}, []
    for lib, symbols in by_lib.items():
        path = index.get(normalize_key(lib))
        if path is None:
            unresolved.append(lib)
            continue
        resolved[lib] = (path, symbols)
        print(f"  {lib:<24} -> {path.relative_to(libs_dir)}")
    for lib in unresolved:
        print(f"  {lib:<24} -> NOT FOUND in mirror")

    if not resolved:
        print("\nNo library resolved; nothing to analyse.", file=sys.stderr)
        return 1

    startfunc_root.mkdir(parents=True, exist_ok=True)
    for lib, (path, symbols) in sorted(resolved.items()):
        f = startfunc_root / f"{path.name}.txt"
        # A library may be bound from several names; merge rather than clobber.
        existing = set(f.read_text().split()) if f.is_file() else set()
        f.write_text("\n".join(sorted(existing | symbols)) + "\n")
    print(f"\nWrote start-function files to {startfunc_root}")

    if not args.run_syspart:
        print("Re-run with --run-syspart to compute syscalls.")
        return 0

    union = set()
    failures = []
    for lib, (path, _symbols) in sorted(resolved.items()):
        startfunc_file = startfunc_root / f"{path.name}.txt"
        out_dir = syscalls_root / path.name
        syscalls_file = out_dir / "syscalls.txt"
        if syscalls_file.is_file() and not args.force:
            print(f"\n[{path.name}] already analysed, skipping (use --force)")
        else:
            print(f"\n[{path.name}] running SysPart over "
                  f"{len(startfunc_file.read_text().split())} start functions...")
            code = run_syspart(syspart_dir, path, out_dir, startfunc_file, user_library_path)
            if code != 0:
                failures.append((path.name, code))
                print(f"  FAILED (exit {code}); see {out_dir / 'logfile.txt'}")
        if syscalls_file.is_file():
            found = {s.strip() for s in syscalls_file.read_text().split() if s.strip()}
            union |= found
            print(f"  {len(found)} syscalls")

    work.mkdir(parents=True, exist_ok=True)
    union_path = work / "union_syscalls.txt"
    union_path.write_text("\n".join(sorted(union)) + ("\n" if union else ""))

    print("\n" + "=" * 60)
    print(f"Union: {len(union)} syscalls -> {union_path}")
    if failures:
        print(f"{len(failures)} library/libraries failed:")
        for name, code in failures:
            print(f"  {name} (exit {code})")
    print("\nFold into the profile with:")
    print(f"  python3 scripts/merge_all_syscalls.py {img}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
