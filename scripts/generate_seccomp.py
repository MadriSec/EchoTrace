#!/usr/bin/env python3
"""
Generate a seccomp profile from syscall text files.

Usage:
  - From a single file:
      python3 generate_seccomp.py --input /path/to/syscalls.txt --output seccomp.json
  - From a directory (all *.txt files):
      python3 generate_seccomp.py --input /path/to/dir --output seccomp.json

Input format:
  - If --input is a directory, all *.txt files in it are read.
  - If --input is a file, only that file is read.
  - Each non-empty, non-comment line is treated as a syscall name.
  - Duplicate syscalls across files are de-duplicated.

Output:
  - A JSON file shaped like Docker-style seccomp profiles, with a single rule
    that allows the collected syscalls and errors everything else.
"""
from __future__ import annotations

import argparse
import json
import pathlib
from typing import Iterable, Set


DEFAULT_ARCHES = [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32",
]


def read_syscalls_from_files(files: Iterable[pathlib.Path]) -> Set[str]:
    syscalls: Set[str] = set()
    for path in files:
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                    continue
                syscalls.add(stripped)
        except FileNotFoundError:
            raise
    return syscalls


def build_seccomp_profile(syscalls: Set[str]) -> dict:
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": DEFAULT_ARCHES,
        "syscalls": [
            {
                "names": sorted(syscalls),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate seccomp.json from syscall text files."
    )
    parser.add_argument(
        "--input",
        required=True,
        type=pathlib.Path,
        help="Path to a syscall .txt file or a directory containing *.txt files.",
    )
    parser.add_argument(
        "--output",
        default="seccomp.json",
        type=pathlib.Path,
        help="Where to write the generated seccomp profile (default: ./seccomp.json).",
    )
    args = parser.parse_args()

    if not args.input.exists():
        raise SystemExit(f"Input not found: {args.input}")

    if args.input.is_dir():
        txt_files = sorted(args.input.glob("*.txt"))
        if not txt_files:
            raise SystemExit(f"No .txt files found in {args.input}")
    else:
        if args.input.suffix.lower() != ".txt":
            raise SystemExit(f"Input file must be .txt: {args.input}")
        txt_files = [args.input]

    syscalls = read_syscalls_from_files(txt_files)
    if not syscalls:
        raise SystemExit("No syscalls found in input files.")

    profile = build_seccomp_profile(syscalls)
    args.output.write_text(json.dumps(profile, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {args.output} with {len(syscalls)} syscalls.")


if __name__ == "__main__":
    main()

