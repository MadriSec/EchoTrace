#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -z "${IMG_NAME:-}" ]; then
  echo "ERROR: IMG_NAME is required" >&2
  exit 1
fi

LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-${PROJECT_ROOT}/LIBS_${IMG_NAME}}}"
OUTPUTS_BASE_DIR="${OUTPUTS_DIR:-${PROJECT_ROOT}/outputs_${IMG_NAME}}"

mkdir -p "$OUTPUTS_BASE_DIR"

echo "============================================================"
echo " Native mapping and start-function preparation"
echo "============================================================"
echo "LIB_DIRS:    $LIBS_BASE_DIR"
echo "OUTPUTS_DIR: $OUTPUTS_BASE_DIR"

echo "  1/3 Running mapped_updated.py"
LIB_DIRS="$LIBS_BASE_DIR" OUTPUTS_DIR="$OUTPUTS_BASE_DIR" \
  python3 "${SCRIPT_DIR}/mapped_updated.py"

echo "  2/3 Filtering unresolved mappings"
IMG_NAME="$IMG_NAME" OUTPUTS_DIR="$OUTPUTS_BASE_DIR" \
  bash "${SCRIPT_DIR}/filter.sh"

echo "  3/3 Writing per-library SysPart start files"
IMG_NAME="$IMG_NAME" OUTPUTS_DIR="$OUTPUTS_BASE_DIR" \
  python3 "${SCRIPT_DIR}/change_format.py" "${OUTPUTS_BASE_DIR}/filtered_method_syscalls.txt" --sort --uniq

echo "Native mapping preparation complete."
