#!/usr/bin/env bash
# organize_results.sh
#
# Moves per-container analysis artifacts into a structured layout under
# Final_results/<IMG_NAME>/.
#
# A run leaves a dozen directories at the repository root -- LIBS_, JARFILES_,
# BINARIES_, RUNTIME_, outputs_, syscalls_output_ and so on -- with no grouping
# beyond the image name in each. This gathers one image's artifacts so a result
# can be archived, copied or compared as a unit.
#
# Usage:
#   ./scripts/organize_results.sh              # process all containers
#   ./scripts/organize_results.sh <IMG_NAME>   # process a single container
#   ./scripts/organize_results.sh --dry-run    # show what would move
#
# Structure per container:
#   Final_results/<IMG_NAME>/
#       Dataset/
#           JARFILES_<IMG_NAME>  LIBS_<IMG_NAME>
#           BINARIES_<IMG_NAME>  RUNTIME_<IMG_NAME>
#       Bytecode_Analysis/
#           outputs_<IMG_NAME>
#       Dynamic_Analysis/
#           sysdig_outputs_<IMG_NAME>
#       Binary_Analysis/
#           syscalls_LIBS_<IMG_NAME>   syscalls_output_<IMG_NAME>
#           syscalls_BIN_<IMG_NAME>    syscalls_unanalysed_<IMG_NAME>
#           startfuncs_unanalysed_<IMG_NAME>   jna_ffi_analysis
#       Reports/
#           dynamic_leftover_* reports, progress logs
#
# Note: results/ is tracked in git and holds the committed evaluation data, so
# collected runs go to Final_results/ instead.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
FINAL="${BASE_DIR}/Final_results"

DRY_RUN=0
args=()
for arg in "$@"; do
    case "$arg" in
        --dry-run) DRY_RUN=1 ;;
        -h|--help) sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) args+=("$arg") ;;
    esac
done

cd "$BASE_DIR"

# ── Build container list ──────────────────────────────────────────────
SINGLE_IMAGE=0
if [ "${#args[@]}" -ge 1 ]; then
    SINGLE_IMAGE=1
    img_list=("$(echo "${args[0]}" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')")
else
    # Auto-discover: outputs_ dirs that have a matching LIBS_ or JARFILES_
    img_list=()
    for d in outputs_*/; do
        [ -d "$d" ] || continue
        name="${d%/}"
        img="${name#outputs_}"
        [ -z "$img" ] && continue
        if [ -d "LIBS_${img}" ] || [ -d "JARFILES_${img}" ]; then
            img_list+=("$img")
        fi
    done
    if [ "${#img_list[@]}" -eq 0 ]; then
        echo "No containers found to organize."
        echo "Expected outputs_<IMG_NAME>/ alongside LIBS_<IMG_NAME>/ or JARFILES_<IMG_NAME>/."
        exit 0
    fi
    mapfile -t img_list < <(printf '%s\n' "${img_list[@]}" | sort -u)
fi

echo "Found ${#img_list[@]} container(s) to organize."
[ "$DRY_RUN" -eq 1 ] && echo "(dry run: nothing will be moved)"
echo ""
[ "$DRY_RUN" -eq 1 ] || mkdir -p "$FINAL"

moved=0

# relocate <source name> <destination subdirectory> <image>
relocate() {
    local src_name="$1" subdir="$2" img="$3"
    local src="${BASE_DIR}/${src_name}"
    local target="${FINAL}/${img}/${subdir}/${src_name}"
    [ -e "$src" ] || return 0
    if [ -e "$target" ]; then
        echo "      skip ${src_name} (already in ${subdir}/)"
        return 0
    fi
    local size
    size="$(du -sh "$src" 2>/dev/null | cut -f1 || echo '?')"
    echo "      ${src_name}  (${size}) -> ${subdir}/"
    if [ "$DRY_RUN" -eq 0 ]; then
        mkdir -p "${FINAL}/${img}/${subdir}"
        mv "$src" "$target"
    fi
    moved=$((moved + 1))
}

for img in "${img_list[@]}"; do
    echo "  ${img}"
    before=$moved

    for prefix in JARFILES LIBS BINARIES RUNTIME; do
        relocate "${prefix}_${img}" "Dataset" "$img"
    done

    relocate "outputs_${img}"        "Bytecode_Analysis" "$img"
    relocate "sysdig_outputs_${img}" "Dynamic_Analysis"  "$img"

    for prefix in syscalls_LIBS syscalls_output syscalls_BIN \
                  syscalls_unanalysed startfuncs_unanalysed; do
        relocate "${prefix}_${img}" "Binary_Analysis" "$img"
    done
    # jna_ffi_analysis and the leftover reports are not per-image: they are
    # overwritten by each run and carry no image name. Attributing them while
    # organizing several containers would hand them to whichever is processed
    # first and silently give the rest nothing, so only claim them when a
    # single image was named explicitly.
    if [ "$SINGLE_IMAGE" -eq 1 ]; then
        relocate "jna_ffi_analysis" "Binary_Analysis" "$img"
        for f in dynamic_leftover_after_analyzed_ldd.* unanalysed_syspart_progress.log; do
            [ -e "${BASE_DIR}/${f}" ] || continue
            relocate "$f" "Reports" "$img"
        done
    fi

    echo "    ($((moved - before)) moved)"
done

echo ""
if [ "$DRY_RUN" -eq 1 ]; then
    echo "Dry run: ${moved} item(s) would move into ${FINAL}/"
else
    echo "Done. Moved ${moved} item(s) into ${FINAL}/"
fi
echo "Containers organized: ${#img_list[@]}"

if [ "$SINGLE_IMAGE" -eq 0 ]; then
    for f in jna_ffi_analysis dynamic_leftover_after_analyzed_ldd.summary.tsv; do
        if [ -e "${BASE_DIR}/${f}" ]; then
            echo ""
            echo "Left in place: jna_ffi_analysis and the dynamic_leftover reports are"
            echo "not per-image. Name a single container to file them under it:"
            echo "  $0 <IMG_NAME>"
            break
        fi
    done
fi
