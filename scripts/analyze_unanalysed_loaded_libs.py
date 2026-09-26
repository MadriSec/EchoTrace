#!/usr/bin/env python3
"""
Analyse dynamically loaded libraries that no Java binding reaches.

Libraries observed at runtime but never mapped from a Java native method are
invisible to the bytecode-driven pipeline, so their syscalls are missing from
the generated profile. For each such library this script:

  1. resolves the loaded soname to a file inside LIBS_<IMG_NAME>
  2. extracts every exported function (nm -D --defined-only, types T/W/I)
  3. writes those as a SysPart start-function file
  4. optionally runs SysPart over them (--run-syspart)

Using all exported functions as entry points is deliberately conservative:
without a Java entry point there is no way to know which exports are reachable,
so every one is treated as a potential entry.

Input is the leftover list from report_dynamic_leftover_after_analyzed_ldd.py.
Output syscalls land in syscalls_unanalysed_<IMG_NAME>/, which
merge_all_syscalls.py unions into the final allowlist.

Usage:
  IMG_NAME=tomcat_9.0.120 ./scripts/analyze_unanalysed_loaded_libs.py --run-syspart
"""
import argparse
from datetime import datetime
import os
import re
import subprocess
import sys
from pathlib import Path


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


def run_text(cmd, timeout=30, env=None, cwd=None):
    try:
        proc = subprocess.run(
            cmd, check=False, text=True,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
            timeout=timeout, env=env, cwd=str(cwd) if cwd else None,
        )
        return proc.stdout
    except subprocess.TimeoutExpired:
        return ""


def read_soname(path):
    out = run_text(["readelf", "-d", str(path)], timeout=5)
    match = SONAME_RE.search(out)
    return match.group(1) if match else None


def parse_leftover_file(path):
    """Parses the grouped '<name> (<count>)' / '  - <lib>' report format."""
    grouped = {}
    current = None
    for raw in path.read_text(errors="replace").splitlines():
        line = raw.rstrip()
        if not line:
            current = None
            continue
        header = re.match(r"^(\S+) \((\d+)\)$", line)
        if header:
            current = header.group(1)
            grouped.setdefault(current, [])
            continue
        item = re.match(r"^\s+-\s+(.+)$", line)
        if current and item:
            grouped[current].append(item.group(1).strip())
    return grouped


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
        variant = dash_variant(path.name)
        if variant:
            by_name.setdefault(variant, []).append(path)
        soname = read_soname(path)
        if soname:
            by_name.setdefault(soname, []).append(path)
            by_name.setdefault(normalize_name(soname), []).append(path)
    return lib_paths, by_name


def resolve_name(name, by_name):
    candidates = by_name.get(name) or by_name.get(normalize_name(name)) or []
    if not candidates:
        variant = dash_variant(name)
        candidates = by_name.get(variant, []) if variant else []
    if not candidates:
        return None
    return sorted(candidates, key=lambda p: (len(p.parts), str(p)))[0]


def exported_functions(path):
    out = run_text(["nm", "-D", "--defined-only", str(path)], timeout=20)
    funcs = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 3:
            continue
        sym_type = parts[-2]
        # nm includes ELF symbol versions (foo@@VERSION), while SysPart's
        # allfunctions.txt records the unversioned function name.
        sym_name = parts[-1].split("@", 1)[0]
        if sym_type.upper() in {"T", "W", "I"}:
            funcs.add(sym_name)
    return sorted(funcs)


def build_user_library_path(libs_dir):
    paths = [str(libs_dir)]
    for jdk_dir in sorted(libs_dir.glob("JDK*_LIBS")):
        if not jdk_dir.is_dir():
            continue
        paths.append(str(jdk_dir))
        for subdir in sorted(p for p in jdk_dir.rglob("*") if p.is_dir()):
            paths.append(str(subdir))
    return ":".join(paths)


def run_syspart(syspart_dir, binary_path, output_dir, startfunc_file, user_library_path):
    app_dir = syspart_dir / "analysis" / "app"
    compute = app_dir / "src" / "scripts" / "compute_syscalls.sh"
    output_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["USER_LIBRARY_PATH"] = user_library_path
    log_path = output_dir / "logfile.txt"
    with log_path.open("ab") as log:
        proc = subprocess.run(
            [str(compute), str(binary_path), str(output_dir), str(startfunc_file), "--log"],
            cwd=str(app_dir), env=env, stdout=log, stderr=subprocess.STDOUT, check=False,
        )
    required = output_dir / "startfuncs_with_addr.txt"
    syscalls = output_dir / "syscalls.txt"
    if proc.returncode == 0 and (not required.is_file() or required.stat().st_size == 0):
        return 66
    if proc.returncode == 0 and not syscalls.is_file():
        return 67
    return proc.returncode


def syspart_output_complete(output_dir, startfunc_file):
    startfuncs = output_dir / "startfuncs_with_addr.txt"
    syscalls = output_dir / "syscalls.txt"
    return (
        startfuncs.is_file()
        and startfuncs.stat().st_size > 0
        and syscalls.is_file()
        and startfuncs.stat().st_mtime_ns >= startfunc_file.stat().st_mtime_ns
        and syscalls.stat().st_mtime_ns >= startfunc_file.stat().st_mtime_ns
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--img-name", default=os.environ.get("IMG_NAME"),
                        help="Image identifier (defaults to $IMG_NAME)")
    parser.add_argument("--project-root", default=None,
                        help="Repository root (defaults to the parent of scripts/)")
    parser.add_argument("--libs-dir", default=None, help="Override LIBS_<IMG_NAME>")
    parser.add_argument("--leftovers", default=None,
                        help="Leftover report (defaults to "
                             "<root>/dynamic_leftover_after_analyzed_ldd.leftover_by_container.txt)")
    parser.add_argument("--syspart-dir", default=None,
                        help="SysPart checkout (defaults to <root>/SysPartCode)")
    parser.add_argument("--run-syspart", action="store_true",
                        help="Run SysPart after writing the start-function files")
    parser.add_argument("--force", action="store_true", help="Rerun already-complete SysPart outputs")
    args = parser.parse_args()

    if not args.img_name:
        parser.error("IMG_NAME is required (pass --img-name or set $IMG_NAME)")

    img = args.img_name
    root = Path(args.project_root).resolve() if args.project_root \
        else Path(__file__).resolve().parent.parent

    libs_dir = Path(args.libs_dir).resolve() if args.libs_dir else root / ("LIBS_%s" % img)
    leftovers_path = Path(args.leftovers).resolve() if args.leftovers \
        else root / "dynamic_leftover_after_analyzed_ldd.leftover_by_container.txt"
    syspart_dir = Path(args.syspart_dir).resolve() if args.syspart_dir else root / "SysPartCode"

    startfunc_root = root / ("startfuncs_unanalysed_%s" % img)
    output_root = root / ("syscalls_unanalysed_%s" % img)
    progress_path = root / "unanalysed_syspart_progress.log"
    run_path = root / "dynamic_leftover_after_analyzed_ldd.unanalysed_syspart_runs.tsv"
    prepared_path = root / "dynamic_leftover_after_analyzed_ldd.unanalysed_startfuncs.tsv"

    print("=" * 60)
    print(" Analysing unanalysed dynamically loaded libraries")
    print("=" * 60)
    print("IMG_NAME:  %s" % img)
    print("LIBS:      %s" % libs_dir)
    print("leftovers: %s" % leftovers_path)
    print("run-syspart: %s" % args.run_syspart)

    if not libs_dir.is_dir():
        print("ERROR: LIBS directory not found: %s" % libs_dir, file=sys.stderr)
        return 1
    if not leftovers_path.is_file():
        print("ERROR: leftover report not found: %s" % leftovers_path, file=sys.stderr)
        print("       Run scripts/report_dynamic_leftover_after_analyzed_ldd.py first.",
              file=sys.stderr)
        return 1

    grouped = parse_leftover_file(leftovers_path)
    # Flat layout: one image per run, but accept any grouping key so reports
    # produced elsewhere still parse.
    leftovers = grouped.get(img)
    if leftovers is None:
        leftovers = [name for names in grouped.values() for name in names]

    def progress(message):
        line = "%s %s" % (datetime.now().isoformat(timespec="seconds"), message)
        print(line, flush=True)
        with progress_path.open("a") as fh:
            fh.write(line + "\n")

    if args.run_syspart:
        with run_path.open("w") as fh:
            fh.write("image\tloaded_name\tresolved_relpath\toutput_dir\tstatus\texit_code\n")
        progress("RUN image=%s libraries=%d force=%s" % (img, len(leftovers), args.force))

    if not leftovers:
        print("\nNothing to do: no unanalysed libraries reported.")
        return 0

    progress("INDEX %s" % libs_dir)
    _, by_name = build_lib_index(libs_dir)
    user_library_path = build_user_library_path(libs_dir)

    prepared_rows = []
    total = len(leftovers)
    for index, loaded_name in enumerate(sorted(leftovers), start=1):
        prefix = "[%d/%d] %s" % (index, total, loaded_name)
        resolved = resolve_name(loaded_name, by_name)
        if not resolved:
            prepared_rows.append([img, loaded_name, "", "", "0", "unresolved"])
            progress("UNRESOLVED %s" % prefix)
            continue

        rel = resolved.relative_to(libs_dir)
        funcs = exported_functions(resolved)
        startfunc_file = startfunc_root / rel.with_suffix(rel.suffix + ".txt")
        startfunc_file.parent.mkdir(parents=True, exist_ok=True)
        content = "\n".join(funcs) + ("\n" if funcs else "")
        if not startfunc_file.is_file() or startfunc_file.read_text(errors="replace") != content:
            startfunc_file.write_text(content)

        status = "ok" if funcs else "no_exported_functions"
        prepared_rows.append([img, loaded_name, str(rel), str(startfunc_file),
                              str(len(funcs)), status])

        if args.run_syspart and funcs:
            output_dir = output_root / rel
            if not args.force and syspart_output_complete(output_dir, startfunc_file):
                run_status, exit_code = "skipped_complete", 0
                progress("SKIP %s already_complete" % prefix)
            else:
                progress("START %s functions=%d log=%s"
                         % (prefix, len(funcs), output_dir / "logfile.txt"))
                exit_code = run_syspart(syspart_dir, resolved, output_dir,
                                        startfunc_file, user_library_path)
                run_status = "completed" if exit_code == 0 else "failed"
                syscalls_file = output_dir / "syscalls.txt"
                count = len(syscalls_file.read_text(errors="replace").splitlines()) \
                    if syscalls_file.is_file() else 0
                progress("DONE %s status=%s exit=%d syscalls=%d"
                         % (prefix, run_status, exit_code, count))

            with run_path.open("a") as fh:
                fh.write("\t".join([img, loaded_name, str(rel), str(output_dir),
                                    run_status, str(exit_code)]) + "\n")
        elif args.run_syspart:
            progress("SKIP %s no_exported_functions" % prefix)

    with prepared_path.open("w") as fh:
        fh.write("image\tloaded_name\tresolved_relpath\tstartfunc_file\t"
                 "exported_function_count\tstatus\n")
        for row in prepared_rows:
            fh.write("\t".join(row) + "\n")

    print("\nprepared=%s" % prepared_path)
    if args.run_syspart:
        print("runs=%s" % run_path)
        print("progress=%s" % progress_path)
        print("syscalls=%s" % output_root)

    by_status = {}
    for row in prepared_rows:
        by_status[row[-1]] = by_status.get(row[-1], 0) + 1
    for status, count in sorted(by_status.items()):
        print("%s=%d" % (status, count))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
