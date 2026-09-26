#!/usr/bin/env python3
"""
Report dynamically loaded libraries that binary analysis never covered.

A library observed at runtime contributes syscalls only if SysPart analysed it.
Three sets are compared:

  dynamic  - shared objects the container actually opened (sysdig capture)
  analyzed - libraries that already have a syscalls_output_<IMG_NAME>/<lib>/ tree
  ldd_deps - transitive ldd closure of the analyzed libraries, i.e. libraries
             that are already covered indirectly because an analyzed library
             links against them

  leftover = dynamic - analyzed - ldd_deps

The leftover set is what an allowlist would silently miss: loaded at runtime,
reachable from no Java binding, and not pulled in as a dependency of anything
analysed. analyze_unanalysed_loaded_libs.py consumes this list.

Usage:
  IMG_NAME=tomcat_9.0.120 ./scripts/report_dynamic_leftover_after_analyzed_ldd.py
"""
import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


LDD_NAME_RE = re.compile(r"^\s*(\S+)\s+=>")
LDD_DIRECT_RE = re.compile(r"^\s*(/[^ ]+)")
SONAME_RE = re.compile(r"\(SONAME\)\s+Library soname: \[(.+)\]")

PRUNED_DIRS = {".git", ".github", "doc", "docs", "test", "tests", "examples"}


def is_real_so_name(name):
    return (
        ".so" in name
        and not name.endswith(".lck")
        and not name.startswith("ld.so")
        and not name.startswith("ld-linux")
    )


def normalize_name(name):
    if ".so" in name:
        return name[: name.index(".so") + 3]
    return name


def dash_variant(name):
    match = re.match(r"^(lib[^.]+)\.so\.(.+)$", name)
    if not match:
        return None
    return "%s-" % match.group(1)


def read_soname(path):
    try:
        proc = subprocess.run(
            ["readelf", "-d", str(path)],
            check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=5,
        )
    except subprocess.TimeoutExpired:
        return None
    match = SONAME_RE.search(proc.stdout)
    return match.group(1) if match else None


def dynamic_loaded_names(sysdig_dir):
    """Shared objects the container opened, from the sysdig capture."""
    names = set()
    loaded_file = sysdig_dir / "jni_libs_opened.txt"
    if not loaded_file.exists():
        return names
    for line in loaded_file.read_text(errors="replace").splitlines():
        base = Path(line.strip()).name
        if is_real_so_name(base):
            names.add(base)
    return names


def analyzed_names(syscalls_dir):
    """Libraries that already have a SysPart output directory."""
    if not syscalls_dir.exists():
        return set()
    return {p.name for p in syscalls_dir.iterdir() if p.is_dir() and is_real_so_name(p.name)}


def build_lib_index(libs_dir):
    lib_paths = []
    base_depth = len(libs_dir.parts)
    for current, dirs, files in os.walk(libs_dir):
        depth = len(Path(current).parts) - base_depth
        if depth >= 5:
            dirs[:] = []
        dirs[:] = [d for d in dirs if d not in PRUNED_DIRS]
        for file_name in files:
            if is_real_so_name(file_name):
                lib_paths.append(Path(current) / file_name)

    by_name = {}
    for path in lib_paths:
        by_name.setdefault(path.name, []).append(path)
        by_name.setdefault(normalize_name(path.name), []).append(path)
        soname = read_soname(path)
        if soname:
            by_name.setdefault(soname, []).append(path)
            by_name.setdefault(normalize_name(soname), []).append(path)
        variant = dash_variant(path.name)
        if variant:
            by_name.setdefault(variant, []).append(path)
    return lib_paths, by_name


def resolve_name(name, by_name):
    candidates = by_name.get(name) or by_name.get(normalize_name(name)) or []
    if not candidates:
        variant = dash_variant(name)
        candidates = by_name.get(variant, []) if variant else []
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: (len(p.parts), str(p)))[0]


def ldd_names(path):
    try:
        proc = subprocess.run(
            ["ldd", str(path)],
            check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=10,
        )
        output = proc.stdout
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""

    deps = set()
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("linux-vdso"):
            continue
        match = LDD_NAME_RE.match(line)
        if match and is_real_so_name(match.group(1)):
            deps.add(match.group(1))
            continue
        match = LDD_DIRECT_RE.match(line)
        if match:
            base = Path(match.group(1)).name
            if is_real_so_name(base):
                deps.add(base)
    return deps


def ldd_dependency_closure(roots, by_name):
    deps = set()
    unresolved = []
    queued = sorted(roots)
    seen_paths = set()

    while queued:
        name = queued.pop(0)
        resolved = resolve_name(name, by_name)
        if not resolved:
            unresolved.append(name)
            continue
        resolved_key = str(resolved)
        if resolved_key in seen_paths:
            continue
        seen_paths.add(resolved_key)
        for dep in sorted(ldd_names(resolved)):
            if dep not in deps:
                deps.add(dep)
                queued.append(dep)

    return deps, sorted(set(unresolved))


def write_names(path, img_name, names):
    """Grouped format shared with analyze_unanalysed_loaded_libs.py."""
    with path.open("w") as fh:
        fh.write("%s (%d)\n" % (img_name, len(names)))
        for name in names:
            fh.write("  - %s\n" % name)
        fh.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--img-name", default=os.environ.get("IMG_NAME"),
                        help="Image identifier (defaults to $IMG_NAME)")
    parser.add_argument("--project-root", default=None,
                        help="Repository root (defaults to the parent of scripts/)")
    parser.add_argument("--libs-dir", default=None, help="Override LIBS_<IMG_NAME>")
    parser.add_argument("--syscalls-dir", default=None, help="Override syscalls_output_<IMG_NAME>")
    parser.add_argument("--sysdig-dir", default=None, help="Override sysdig_outputs_<IMG_NAME>")
    parser.add_argument("--out-prefix", default=None,
                        help="Output prefix (defaults to <root>/dynamic_leftover_after_analyzed_ldd)")
    args = parser.parse_args()

    if not args.img_name:
        parser.error("IMG_NAME is required (pass --img-name or set $IMG_NAME)")

    img = args.img_name
    root = Path(args.project_root).resolve() if args.project_root \
        else Path(__file__).resolve().parent.parent

    libs_dir = Path(args.libs_dir).resolve() if args.libs_dir else root / ("LIBS_%s" % img)
    syscalls_dir = Path(args.syscalls_dir).resolve() if args.syscalls_dir \
        else root / ("syscalls_output_%s" % img)
    sysdig_dir = Path(args.sysdig_dir).resolve() if args.sysdig_dir \
        else root / ("sysdig_outputs_%s" % img)
    out_prefix = Path(args.out_prefix).resolve() if args.out_prefix \
        else root / "dynamic_leftover_after_analyzed_ldd"

    print("=" * 60)
    print(" Unanalysed dynamically loaded libraries")
    print("=" * 60)
    print("IMG_NAME:     %s" % img)
    print("LIBS:         %s" % libs_dir)
    print("syscalls_out: %s" % syscalls_dir)
    print("sysdig_out:   %s" % sysdig_dir)

    if not libs_dir.is_dir():
        print("ERROR: LIBS directory not found: %s" % libs_dir, file=sys.stderr)
        return 1

    dynamic = dynamic_loaded_names(sysdig_dir)
    analyzed = analyzed_names(syscalls_dir)
    if not dynamic:
        print("\nWARNING: no dynamically loaded libraries found in %s" % sysdig_dir)
        print("         (expected jni_libs_opened.txt from the sysdig capture)")

    _, by_name = build_lib_index(libs_dir)
    ldd_deps, unresolved = ldd_dependency_closure(analyzed, by_name)
    leftover = sorted(dynamic - analyzed - ldd_deps)

    names_path = out_prefix.with_suffix(".leftover_by_container.txt")
    summary_path = out_prefix.with_suffix(".summary.tsv")
    deps_path = out_prefix.with_suffix(".ldd_deps_by_container.txt")

    write_names(names_path, img, leftover)
    write_names(deps_path, img, sorted(ldd_deps))
    with summary_path.open("w") as fh:
        fh.write("image\tdynamic\tanalyzed\tldd_deps\tdynamic_analyzed\t"
                 "dynamic_ldd\tleftover\tunresolved_analyzed\n")
        fh.write("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n" % (
            img, len(dynamic), len(analyzed), len(ldd_deps),
            len(dynamic & analyzed), len(dynamic & ldd_deps),
            len(leftover), len(unresolved),
        ))

    print("\nloaded at runtime:          %d" % len(dynamic))
    print("already analysed:           %d" % len(analyzed))
    print("covered via ldd closure:    %d" % len(ldd_deps))
    print("LEFTOVER (unanalysed):      %d" % len(leftover))
    if unresolved:
        print("analyzed names unresolved:  %d" % len(unresolved))
    for name in leftover:
        print("  - %s" % name)

    print("\nwrote %s" % names_path)
    print("wrote %s" % summary_path)
    print("wrote %s" % deps_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
