#!/usr/bin/env python3
"""
Script: merge_all_syscalls.py
Description: Merge syscalls from binary and library analysis directories and generate seccomp profile

This script:
  1. Parses syscalls_BIN_<IMG_NAME>/<binary>/syscalls.txt files
  2. Reports empty syscalls.txt files in binaries
  3. Creates binary_syscalls.txt with unique syscalls from all binaries
  4. Parses syscalls_LIBS_<IMG_NAME>/<library>/syscalls.txt files
  5. Reports empty syscalls.txt files in libraries
  6. Creates library_syscalls.txt with unique syscalls from all libraries
  7. Parses syscalls_unanalysed_<IMG_NAME>/**/syscalls.txt (dynamically loaded
     libraries that no Java binding reaches; see
     scripts/analyze_unanalysed_loaded_libs.py)
  8. Includes jna_ffi_analysis/union_syscalls.txt when present
  9. Merges with runc.txt default whitelist (if present)
 10. Creates <IMG_NAME>.txt with combined syscalls (no duplicates)
 11. Generates <IMG_NAME>.json seccomp profile from combined syscalls

Usage: ./merge_all_syscalls.py <IMG_NAME> [--skip-unanalysed] [--skip-jna-ffi]

Example:
  ./merge_all_syscalls.py jetty_9.4.58-jdk8-amazoncorretto

Note: Place runc.txt in the repository root to include default runtime syscalls.
"""

import os
import sys
import json
from pathlib import Path
from typing import Set, List, Tuple


DEFAULT_SECCOMP_ARCHES = [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32",
]


def read_syscalls_file(filepath: Path) -> Set[str]:
    """Read syscalls from a file and return as a set (removes duplicates)."""
    syscalls = set()

    if not filepath.exists():
        return syscalls

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                if line:  # Skip empty lines
                    syscalls.add(line)
    except Exception as e:
        print(f"  ⚠ Error reading {filepath}: {e}")

    return syscalls


def process_directory(base_dir: Path, dir_type: str) -> Tuple[Set[str], List[str], List[str]]:
    """
    Process a directory (syscalls_BIN_* or syscalls_LIBS_*) and collect syscalls.

    Returns:
        - Set of all unique syscalls
        - List of subdirectories with empty syscalls.txt
        - List of subdirectories with missing syscalls.txt
    """
    all_syscalls = set()
    empty_files = []
    missing_files = []

    if not base_dir.exists():
        print(f"⚠ Warning: Directory does not exist: {base_dir}")
        return all_syscalls, empty_files, missing_files

    # Get all subdirectories
    subdirs = [d for d in base_dir.iterdir() if d.is_dir()]

    if not subdirs:
        print(f"⚠ Warning: No subdirectories found in {base_dir}")
        return all_syscalls, empty_files, missing_files

    print(f"\n[Processing {dir_type}]")
    print(f"Directory: {base_dir}")
    print(f"Found {len(subdirs)} subdirectories")
    print("")

    for subdir in sorted(subdirs):
        syscalls_file = subdir / "syscalls.txt"
        subdir_name = subdir.name

        if not syscalls_file.exists():
            missing_files.append(subdir_name)
            print(f"  ✗ {subdir_name}: syscalls.txt MISSING")
            continue

        syscalls = read_syscalls_file(syscalls_file)

        if len(syscalls) == 0:
            empty_files.append(subdir_name)
            print(f"  ⚠ {subdir_name}: syscalls.txt EMPTY (0 syscalls)")
        else:
            print(f"  ✓ {subdir_name}: {len(syscalls)} syscalls")
            all_syscalls.update(syscalls)

    return all_syscalls, empty_files, missing_files


def process_syscall_tree(base_dir: Path, dir_type: str) -> Tuple[Set[str], List[str], List[str]]:
    """
    Recursively collect every syscalls.txt below a directory.

    Unlike process_directory(), which expects one level of per-library
    subdirectories, the unanalysed-library outputs mirror the LIBS_ tree and
    can nest arbitrarily deep.
    """
    all_syscalls = set()
    empty_files = []
    missing_files = []

    if not base_dir.exists():
        print(f"Warning: Directory does not exist: {base_dir}")
        return all_syscalls, empty_files, missing_files

    syscall_files = sorted(base_dir.rglob("syscalls.txt"))
    print(f"\n[Processing {dir_type}]")
    print(f"Directory: {base_dir}")
    print(f"Found {len(syscall_files)} syscalls.txt files")

    for syscalls_file in syscall_files:
        relative_parent = str(syscalls_file.parent.relative_to(base_dir))
        syscalls = read_syscalls_file(syscalls_file)
        if syscalls:
            print(f"  {relative_parent}: {len(syscalls)} syscalls")
            all_syscalls.update(syscalls)
        else:
            print(f"  {relative_parent}: syscalls.txt EMPTY (0 syscalls)")
            empty_files.append(relative_parent)

    return all_syscalls, empty_files, missing_files


def write_syscalls_file(filepath: Path, syscalls: Set[str]):
    """Write syscalls to a file, sorted alphabetically."""
    try:
        with open(filepath, 'w') as f:
            for syscall in sorted(syscalls):
                f.write(f"{syscall}\n")
        print(f"  ✓ Written: {filepath} ({len(syscalls)} syscalls)")
    except Exception as e:
        print(f"  ✗ Error writing {filepath}: {e}")


def build_seccomp_profile(syscalls: Set[str]) -> dict:
    """
    Build a seccomp profile from syscall names.

    Returns a Docker-style seccomp profile that:
    - Allows the specified syscalls (SCMP_ACT_ALLOW)
    - Denies all other syscalls with EPERM (SCMP_ACT_ERRNO)
    """
    return {
        "defaultAction": "SCMP_ACT_ERRNO",
        "architectures": DEFAULT_SECCOMP_ARCHES,
        "syscalls": [
            {
                "names": sorted(syscalls),
                "action": "SCMP_ACT_ALLOW",
            }
        ],
    }


def write_seccomp_profile(filepath: Path, syscalls: Set[str]):
    """Generate and write a seccomp profile JSON file."""
    try:
        profile = build_seccomp_profile(syscalls)
        with open(filepath, 'w') as f:
            json.dump(profile, f, indent=2)
            f.write("\n")
        print(f"  ✓ Written: {filepath} ({len(syscalls)} syscalls)")
    except Exception as e:
        print(f"  ✗ Error writing {filepath}: {e}")


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    flags = {a for a in sys.argv[1:] if a.startswith("--")}
    unknown = flags - {"--skip-unanalysed", "--skip-jna-ffi"}
    if len(args) != 1 or unknown:
        if unknown:
            print(f"Unknown option(s): {', '.join(sorted(unknown))}")
        print("Usage: ./merge_all_syscalls.py <IMG_NAME> [--skip-unanalysed] [--skip-jna-ffi]")
        print("")
        print("Example:")
        print("  ./merge_all_syscalls.py jetty_9.4.58-jdk8-amazoncorretto")
        sys.exit(1)

    img_name = args[0]
    skip_unanalysed = "--skip-unanalysed" in flags
    skip_jna_ffi = "--skip-jna-ffi" in flags
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent if script_dir.name == "scripts" else script_dir

    print("╔══════════════════════════════════════════════════════════════╗")
    print("║              Syscall Merge & Analysis Tool                   ║")
    print("╚══════════════════════════════════════════════════════════════╝")
    print(f"\nIMG_NAME: {img_name}")
    print(f"Working directory: {project_root}")

    # Define directories
    bin_dir = project_root / f"syscalls_BIN_{img_name}"
    libs_dir = project_root / f"syscalls_output_{img_name}"

    # =========================================================================
    # STEP 1: Process Binary Syscalls
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 1: Processing Binary Syscalls")
    print("="*70)

    binary_syscalls, bin_empty, bin_missing = process_directory(bin_dir, "Binaries")

    if bin_empty:
        print(f"\n⚠ Warning: {len(bin_empty)} binaries with EMPTY syscalls.txt:")
        for name in bin_empty:
            print(f"    - {name}")

    if bin_missing:
        print(f"\n✗ Error: {len(bin_missing)} binaries with MISSING syscalls.txt:")
        for name in bin_missing:
            print(f"    - {name}")

    # Write binary_syscalls.txt
    print("")
    if binary_syscalls:
        binary_output = bin_dir / "binary_syscalls.txt"
        write_syscalls_file(binary_output, binary_syscalls)
    else:
        print("  ⚠ No syscalls found in any binary, skipping binary_syscalls.txt")

    # =========================================================================
    # STEP 2: Process Library Syscalls
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 2: Processing Library Syscalls")
    print("="*70)

    library_syscalls, lib_empty, lib_missing = process_directory(libs_dir, "Libraries")

    if lib_empty:
        print(f"\n⚠ Warning: {len(lib_empty)} libraries with EMPTY syscalls.txt:")
        for name in lib_empty:
            print(f"    - {name}")

    if lib_missing:
        print(f"\n✗ Error: {len(lib_missing)} libraries with MISSING syscalls.txt:")
        for name in lib_missing:
            print(f"    - {name}")

    # Write library_syscalls.txt
    print("")
    if library_syscalls:
        library_output = libs_dir / "library_syscalls.txt"
        write_syscalls_file(library_output, library_syscalls)
    else:
        print("  ⚠ No syscalls found in any library, skipping library_syscalls.txt")

    # =========================================================================
    # STEP 3: Process Unanalysed Dynamically Loaded Libraries
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 3: Processing Unanalysed Dynamically Loaded Libraries")
    print("="*70)

    unanalysed_dir = project_root / f"syscalls_unanalysed_{img_name}"
    unanalysed_syscalls = set()

    if skip_unanalysed:
        print("\nSkipping unanalysed-library syscalls (--skip-unanalysed).")
    else:
        unanalysed_syscalls, unanalysed_empty, _ = process_syscall_tree(
            unanalysed_dir, "Unanalysed dynamically loaded libraries"
        )
        if unanalysed_empty:
            print(f"\n⚠ Warning: {len(unanalysed_empty)} unanalysed libraries with EMPTY syscalls.txt")
        if unanalysed_dir.exists():
            write_syscalls_file(unanalysed_dir / "unanalysed_syscalls.txt", unanalysed_syscalls)
        else:
            print(f"\n  No unanalysed-library output at {unanalysed_dir}")
            print("  Run scripts/analyze_unanalysed_loaded_libs.py --run-syspart to generate it.")

    # =========================================================================
    # STEP 4: Load JNA/FFI Reachable Syscalls
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 4: Loading JNA/FFI Reachable Syscalls")
    print("="*70)

    jna_ffi_syscalls = set()
    jna_ffi_candidates = [
        project_root / "jna_ffi_analysis" / "union_syscalls.txt",
        project_root / "jna_ffi_analysis" / "full_deps" / "union_syscalls.txt",
    ]

    if skip_jna_ffi:
        print("\nSkipping JNA/FFI syscall union (--skip-jna-ffi).")
    else:
        jna_ffi_path = next((p for p in jna_ffi_candidates if p.exists()), None)
        if jna_ffi_path:
            print(f"\nReading JNA/FFI syscall union from: {jna_ffi_path}")
            jna_ffi_syscalls = read_syscalls_file(jna_ffi_path)
            print(f"  ✓ Loaded {len(jna_ffi_syscalls)} syscalls from JNA/FFI analysis")
        else:
            print("\nNo JNA/FFI syscall union found. Looked for:")
            for candidate in jna_ffi_candidates:
                print(f"    - {candidate}")

    # =========================================================================
    # STEP 5: Load runc.txt Default Whitelist
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 5: Loading runc.txt Default Whitelist")
    print("="*70)

    runc_whitelist_path = project_root / "runc.txt"
    runc_syscalls = set()

    if runc_whitelist_path.exists():
        print(f"\nReading default whitelist from: {runc_whitelist_path}")
        runc_syscalls = read_syscalls_file(runc_whitelist_path)
        print(f"  ✓ Loaded {len(runc_syscalls)} syscalls from runc.txt")
    else:
        print(f"\n⚠ Warning: runc.txt not found at {runc_whitelist_path}")
        print("  Continuing without default whitelist...")

    # =========================================================================
    # STEP 6: Create Combined Syscalls File
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 6: Creating Combined Syscalls File")
    print("="*70)

    # Combine all sets (set union automatically removes duplicates)
    # Order: binary + library + unanalysed library + JNA/FFI + runc whitelist
    combined_syscalls = (binary_syscalls | library_syscalls | unanalysed_syscalls
                         | jna_ffi_syscalls | runc_syscalls)

    print(f"\nBinary syscalls:      {len(binary_syscalls)}")
    print(f"Library syscalls:     {len(library_syscalls)}")
    print(f"Unanalysed libraries: {len(unanalysed_syscalls)}")
    print(f"JNA/FFI syscalls:     {len(jna_ffi_syscalls)}")
    print(f"Runc whitelist:       {len(runc_syscalls)}")
    print(f"Combined (unique):    {len(combined_syscalls)}")

    # Report what each additional source contributes beyond binary + library
    base = binary_syscalls | library_syscalls
    added_by_unanalysed = len(base | unanalysed_syscalls) - len(base)
    if added_by_unanalysed > 0:
        print(f"  → unanalysed libraries added {added_by_unanalysed} additional syscalls")
    base_u = base | unanalysed_syscalls
    added_by_jna_ffi = len(base_u | jna_ffi_syscalls) - len(base_u)
    if added_by_jna_ffi > 0:
        print(f"  → JNA/FFI analysis added {added_by_jna_ffi} additional syscalls")
    before_runc = len(base_u | jna_ffi_syscalls)
    added_by_runc = len(combined_syscalls) - before_runc
    if added_by_runc > 0:
        print(f"  → runc.txt added {added_by_runc} additional syscalls")
    print("")

    if combined_syscalls:
        # Write to syscalls_LIBS_<IMG_NAME>/<IMG_NAME>.txt
        combined_output = libs_dir / f"{img_name}.txt"
        write_syscalls_file(combined_output, combined_syscalls)
    else:
        print("  ⚠ No syscalls found, skipping combined file")

    # =========================================================================
    # STEP 7: Generate Seccomp Profile
    # =========================================================================
    print("\n" + "="*70)
    print("STEP 7: Generating Seccomp Profile")
    print("="*70)

    if combined_syscalls:
        # Create seccomp profile in syscalls_LIBS_<IMG_NAME>/<IMG_NAME>.json
        seccomp_output = libs_dir / f"{img_name}.json"
        print(f"\nGenerating seccomp profile from combined syscalls...")
        write_seccomp_profile(seccomp_output, combined_syscalls)
        print(f"\nSeccomp profile configuration:")
        print(f"  - Default action: SCMP_ACT_ERRNO (deny all by default)")
        print(f"  - Allowed syscalls: {len(combined_syscalls)}")
        print(f"  - Architectures: {', '.join(DEFAULT_SECCOMP_ARCHES)}")
    else:
        print("\n  ⚠ No syscalls found, skipping seccomp profile generation")

    # =========================================================================
    # STEP 6: Summary
    # =========================================================================
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)

    print(f"\nBinaries:")
    print(f"  - Analyzed:  {len([d for d in bin_dir.iterdir() if d.is_dir()]) if bin_dir.exists() else 0}")
    print(f"  - Empty:     {len(bin_empty)}")
    print(f"  - Missing:   {len(bin_missing)}")
    print(f"  - Syscalls:  {len(binary_syscalls)} unique")

    print(f"\nLibraries:")
    print(f"  - Analyzed:  {len([d for d in libs_dir.iterdir() if d.is_dir()]) if libs_dir.exists() else 0}")
    print(f"  - Empty:     {len(lib_empty)}")
    print(f"  - Missing:   {len(lib_missing)}")
    print(f"  - Syscalls:  {len(library_syscalls)} unique")

    print(f"\nRunc Whitelist:")
    if runc_syscalls:
        print(f"  - Loaded from: {runc_whitelist_path}")
        print(f"  - Syscalls:    {len(runc_syscalls)} unique")
        before_runc = len(binary_syscalls | library_syscalls)
        added_by_runc = len(combined_syscalls) - before_runc
        if added_by_runc > 0:
            print(f"  - Added:       {added_by_runc} additional syscalls")
    else:
        print(f"  - Not loaded (file not found)")

    print(f"\nCombined:")
    print(f"  - Total unique syscalls: {len(combined_syscalls)}")
    if runc_syscalls:
        print(f"  - Includes: binaries + libraries + runc whitelist")

    print(f"\nOutput files:")
    if binary_syscalls:
        print(f"  - {bin_dir / 'binary_syscalls.txt'} (text)")
    if library_syscalls:
        print(f"  - {libs_dir / 'library_syscalls.txt'} (text)")
    if combined_syscalls:
        print(f"  - {libs_dir / f'{img_name}.txt'} (text)")
        print(f"  - {libs_dir / f'{img_name}.json'} (seccomp profile)")

    print("")

    # Exit with error code if there were issues
    if bin_missing or lib_missing or (not combined_syscalls):
        print("⚠ Completed with warnings or errors")
        sys.exit(1)
    else:
        print("✓ Completed successfully")
        sys.exit(0)


if __name__ == "__main__":
    main()
