#!/bin/bash

# Combine all syscalls.txt files under a base directory and output unique syscalls
# Usage:
#   ./combine_syscalls.sh [base_dir] [output_file]
# Defaults:
#   base_dir   = <repo>/syscalls_output (or syscalls_output_<image>)
#   output_file= <base_dir>/unique_syscalls.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Prefer CLI arg; else env SYSCALLS_OUTPUT_DIR; else repo-local default path
BASE_DIR=${1:-${SYSCALLS_OUTPUT_DIR:-${PROJECT_ROOT}/syscalls_output}}
BASE_DIR=${BASE_DIR%/}
OUT_FILE=${2:-"${BASE_DIR}/unique_syscalls.txt"}

if [ ! -d "$BASE_DIR" ]; then
  echo "ERROR: Base directory not found: $BASE_DIR"
  exit 1
fi

echo "Scanning for syscalls.txt under: $BASE_DIR"

mapfile -t FILES < <(find "$BASE_DIR" -type f -name syscalls.txt | sort)

if [ ${#FILES[@]} -eq 0 ]; then
  echo "ERROR: No syscalls.txt files found under $BASE_DIR"
  exit 1
fi

echo "Found ${#FILES[@]} file(s):"
for f in "${FILES[@]}"; do
  echo "  - $f"
done

TMP_OUT=$(mktemp)

# Concatenate, strip comments/whitespace, drop empties, sort unique
{
  for f in "${FILES[@]}"; do
    cat "$f"
  done
} | sed -e 's/#.*$//' -e 's/^\s\+//' -e 's/\s\+$//' |
  awk 'NF > 0' |
  sort -u > "$TMP_OUT"

UNIQUE_COUNT=$(wc -l < "$TMP_OUT")

mkdir -p "$(dirname "$OUT_FILE")"
mv "$TMP_OUT" "$OUT_FILE"

echo "------------------------------------------"
echo "Unique syscalls: $UNIQUE_COUNT"
echo "Output written to: $OUT_FILE"
echo "------------------------------------------"

exit 0


