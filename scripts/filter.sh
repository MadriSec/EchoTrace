#!/usr/bin/env bash
set -euo pipefail

# Determine output directory based on IMG_NAME or OUTPUTS_DIR
IMG_NAME="${IMG_NAME:-}"
OUTPUTS_DIR="${OUTPUTS_DIR:-}"

if [[ -n "$OUTPUTS_DIR" ]]; then
    OUTPUT_BASE="$OUTPUTS_DIR"
elif [[ -n "$IMG_NAME" ]]; then
    OUTPUT_BASE="outputs_${IMG_NAME}"
else
    OUTPUT_BASE="."
fi

# Input defaults to method_syscalls.txt in the output directory
IN="${1:-${OUTPUT_BASE}/mapped_method_syscalls.txt}"
OUT="${2:-${OUTPUT_BASE}/filtered_method_syscalls.txt}"

[[ -f "$IN" ]] || { echo "ERROR: input file '$IN' not found." >&2; exit 1; }

echo "Filtering: $IN -> $OUT"

# Remove CR if the file might be CRLF, drop NOT_FOUND lines, then drop blanks
sed -e 's/\r$//' \
    -e '/NOT_FOUND_IN_LIBS/d' \
    -e '/^[[:space:]]*$/d' \
    "$IN" > "$OUT"

echo "Wrote $(wc -l < "$OUT") lines to $OUT"
