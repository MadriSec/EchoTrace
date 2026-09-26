#!/usr/bin/env bash
#
# Run SysPart against a single library or binary of an already-extracted image.
#
# The full pipeline re-analyses everything, which is wasteful when only one
# artifact needs recomputing — after fixing its dependencies, regenerating its
# start functions, or debugging an empty result.
#
# Usage:
#   IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 LIB_ANALYSE=libnet.so ./scripts/analyse_lib.sh
#
# Optional:
#   STARTFUNC_FILE=/path/to/custom.txt   override the start-function file
#   OUTPUT_DIR=/path/to/out              override the output directory
#   FORCE=1                              overwrite existing output without asking
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ -z "${IMG_NAME:-}" ]; then
    echo "ERROR: IMG_NAME is required" >&2
    echo "  e.g. IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 LIB_ANALYSE=libnet.so $0" >&2
    exit 1
fi
if [ -z "${LIB_ANALYSE:-}" ]; then
    echo "ERROR: LIB_ANALYSE is required (the library or binary name)" >&2
    echo "  e.g. IMG_NAME=${IMG_NAME} LIB_ANALYSE=libnet.so $0" >&2
    exit 1
fi

LIBS_DIR="${LIBS_DIR:-${PROJECT_ROOT}/LIBS_${IMG_NAME}}"
BINARIES_DIR="${BINARIES_DIR:-${PROJECT_ROOT}/BINARIES_${IMG_NAME}}"
OUTPUTS_DIR="${OUTPUTS_DIR:-${PROJECT_ROOT}/outputs_${IMG_NAME}}"
SYSCALLS_DIR="${SYSCALLS_OUTPUT_DIR:-${PROJECT_ROOT}/syscalls_output_${IMG_NAME}}"
SYSPART_DIR="${SYSPART_DIR:-${PROJECT_ROOT}/SysPartCode}"
SYSPART_APP="${SYSPART_DIR}/analysis/app"

if [ ! -x "${SYSPART_APP}/syspart" ]; then
    echo "ERROR: syspart binary not found at ${SYSPART_APP}/syspart" >&2
    echo "       Build it first:  cd ${SYSPART_DIR} && ./build_upgraded_egalito.sh" >&2
    exit 1
fi

echo "============================================================"
echo " Single-artifact SysPart analysis"
echo "============================================================"
echo "IMG_NAME:    ${IMG_NAME}"
echo "LIB_ANALYSE: ${LIB_ANALYSE}"

# --- Locate the artifact -----------------------------------------------------
# Search LIBS first, then BINARIES. Prefer an exact filename match; fall back to
# a versioned match (libnet.so -> libnet.so.1.2.3) so callers can use the plain
# soname. Regular files only: a SONAME symlink would analyse the same file twice
# under two names.
find_artifact() {
    local name="$1" root
    for root in "$LIBS_DIR" "$BINARIES_DIR"; do
        [ -d "$root" ] || continue
        find "$root" -type f -name "$name" 2>/dev/null | awk '{print length"\t"$0}' | sort -n | cut -f2-
        find "$root" -type f -name "${name}.*" 2>/dev/null | awk '{print length"\t"$0}' | sort -n | cut -f2-
    done
}

ARTIFACT="$(find_artifact "$LIB_ANALYSE" | head -1)"
if [ -z "$ARTIFACT" ]; then
    echo "" >&2
    echo "ERROR: '${LIB_ANALYSE}' not found under:" >&2
    echo "  ${LIBS_DIR}" >&2
    echo "  ${BINARIES_DIR}" >&2
    echo "" >&2
    echo "Available (first 40):" >&2
    { [ -d "$LIBS_DIR" ] && find "$LIBS_DIR" -type f -name '*.so*' -printf '  %f\n'; \
      [ -d "$BINARIES_DIR" ] && find "$BINARIES_DIR" -type f -printf '  %f\n'; } 2>/dev/null \
      | sort -u | head -40 >&2
    exit 1
fi
echo "artifact:    ${ARTIFACT}"

BASENAME="$(basename "$ARTIFACT")"

# --- Locate the start-function file ------------------------------------------
# The mapper mirrors the LIBS_ layout under outputs_, so match on filename.
if [ -n "${STARTFUNC_FILE:-}" ]; then
    STARTFUNC="$STARTFUNC_FILE"
else
    STARTFUNC="$(find "$OUTPUTS_DIR" -type f -name "${BASENAME}.txt" 2>/dev/null | head -1)"
fi
if [ -z "$STARTFUNC" ] || [ ! -f "$STARTFUNC" ]; then
    echo "" >&2
    echo "ERROR: no start-function file for '${BASENAME}' under ${OUTPUTS_DIR}" >&2
    echo "" >&2
    echo "Either run the native mapping stage first:" >&2
    echo "  IMG_NAME=${IMG_NAME} bash ${SCRIPT_DIR}/prepare_native_mapping.sh" >&2
    echo "or pass one explicitly with STARTFUNC_FILE=/path/to/file.txt" >&2
    echo "" >&2
    echo "Existing start-function files (first 20):" >&2
    find "$OUTPUTS_DIR" -type f -name '*.txt' 2>/dev/null \
      | grep -v jna_detector_work | head -20 | sed 's|^|  |' >&2
    exit 1
fi
echo "startfuncs:  ${STARTFUNC} ($(wc -l < "$STARTFUNC") functions)"

OUT_DIR="${OUTPUT_DIR:-${SYSCALLS_DIR}/${BASENAME}}"
echo "output:      ${OUT_DIR}"

if [ -s "${OUT_DIR}/syscalls.txt" ] && [ "${FORCE:-0}" != "1" ]; then
    echo ""
    echo "NOTE: ${OUT_DIR}/syscalls.txt already exists"
    echo "      ($(wc -l < "${OUT_DIR}/syscalls.txt") syscalls). It will be overwritten."
    echo "      Set FORCE=1 to skip this notice."
fi
mkdir -p "$OUT_DIR"

# --- Build USER_LIBRARY_PATH -------------------------------------------------
# SysPart resolves each DT_NEEDED name against these directories. The container
# mirror and every subdirectory are included so JDK layouts (JDK*_LIBS/amd64,
# .../server, .../jli) resolve without being enumerated by hand.
#
# NOTE: this is SysPart's own variable, not LD_LIBRARY_PATH. Never export
# LD_LIBRARY_PATH to this directory: the container's glibc will replace the
# host's and break unrelated binaries.
USER_LIBRARY_PATH="$LIBS_DIR"
while IFS= read -r d; do
    USER_LIBRARY_PATH="${USER_LIBRARY_PATH}:${d}"
done < <(find "$LIBS_DIR" -type d 2>/dev/null | sort)
export USER_LIBRARY_PATH

echo ""
echo "Running SysPart..."
echo "------------------------------------------------------------"
( cd "$SYSPART_APP" && ./src/scripts/compute_syscalls.sh \
    "$ARTIFACT" "$OUT_DIR" "$STARTFUNC" --log )
echo "------------------------------------------------------------"

# --- Report ------------------------------------------------------------------
syscall_count=0
[ -f "${OUT_DIR}/syscalls.txt" ] && syscall_count=$(wc -l < "${OUT_DIR}/syscalls.txt")
func_count=0
[ -f "${OUT_DIR}/allfunctions.txt" ] && func_count=$(wc -l < "${OUT_DIR}/allfunctions.txt")

echo ""
echo "Result for ${BASENAME}:"
echo "  functions in call graph: ${func_count}"
echo "  syscalls:                ${syscall_count}"

if [ "$func_count" -eq 0 ]; then
    echo ""
    echo "WARNING: empty call graph. SysPart could not load the artifact or its"
    echo "         dependencies. Check that every DT_NEEDED name resolves inside"
    echo "         ${LIBS_DIR} — extraction drops SONAME symlinks, so a versioned"
    echo "         file may exist without the name the ELF actually asks for:"
    echo "           readelf -d ${ARTIFACT} | grep -i needed"
elif [ "$syscall_count" -eq 0 ]; then
    echo ""
    echo "WARNING: the call graph built, but no syscalls were attributed."
    if [ ! -s "${OUT_DIR}/startfuncs_with_addr.txt" ]; then
        echo "         startfuncs_with_addr.txt is empty/missing, so none of the"
        echo "         start-function names were found in allfunctions.txt."
        echo "         Compare the two:"
        echo "           head -3 ${STARTFUNC}"
        echo "           grep -c . ${OUT_DIR}/allfunctions.txt"
    else
        echo "         Reachable code may genuinely issue no syscalls."
    fi
fi

echo ""
echo "Regenerate the seccomp profile with:"
echo "  python3 ${SCRIPT_DIR}/merge_all_syscalls.py ${IMG_NAME}"
