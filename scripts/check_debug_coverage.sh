#!/usr/bin/env bash
#
# Report debug-symbol coverage across an extracted container mirror.
#
# SysPart seeds entry points from exported dynamic symbols, which survive
# stripping, then walks inward through the library. Local (non-exported)
# functions are what stripping removes, and they are the overwhelming majority:
# libjvm.so exports 255 symbols out of 41,365. Inside a stripped library there
# are no function boundaries or names, so value-flow analysis has less to work
# with when resolving indirect calls -- and an unresolved indirect edge is an
# unexplored subgraph whose syscalls never reach the profile.
#
# That failure is silent and asymmetric: a missing syscall becomes a SIGSYS at
# runtime, not an over-permissive profile. This script measures the exposure.
#
# Usage:
#   IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 ./scripts/check_debug_coverage.sh
#   ./scripts/check_debug_coverage.sh /path/to/LIBS_dir
#
# Optional:
#   DEBUG_DIR=/path/to/debug   look for separate .debug files under
#                              <DEBUG_DIR>/.build-id/<xx>/<rest>.debug
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [ "$#" -ge 1 ]; then
    LIBS_TARGET="$1"
elif [ -n "${LIBS_DIR:-}" ]; then
    LIBS_TARGET="$LIBS_DIR"
elif [ -n "${IMG_NAME:-}" ]; then
    LIBS_TARGET="${PROJECT_ROOT}/LIBS_${IMG_NAME}"
else
    echo "ERROR: provide a directory, or set IMG_NAME or LIBS_DIR" >&2
    echo "  IMG_NAME=tomcat_9.0.120-jdk8-corretto-al2 $0" >&2
    exit 1
fi

if [ ! -d "$LIBS_TARGET" ]; then
    echo "ERROR: not a directory: $LIBS_TARGET" >&2
    exit 1
fi

# Libraries that already produced a SysPart result are the ones whose analysis
# quality is actually at stake right now.
SYSCALLS_DIR="${SYSCALLS_OUTPUT_DIR:-}"
if [ -z "$SYSCALLS_DIR" ] && [ -n "${IMG_NAME:-}" ]; then
    SYSCALLS_DIR="${PROJECT_ROOT}/syscalls_output_${IMG_NAME}"
fi

echo "============================================================"
echo " Debug-symbol coverage"
echo "============================================================"
echo "LIB directory: $LIBS_TARGET"
[ -n "${DEBUG_DIR:-}" ] && echo "Debug store:   $DEBUG_DIR"
echo ""
printf "%-34s %-14s %-12s %s\n" "LIBRARY" "LOCAL SYMS" "BUILD ID" "SEPARATE DEBUG"
printf "%-34s %-14s %-12s %s\n" "----------------------------------" "--------------" "------------" "--------------"

total=0
stripped=0
have_debug=0
want_debug=0
stripped_analysed=0
stripped_list=""
reached_list=""

while IFS= read -r lib; do
    name="$(basename "$lib")"

    # The mirror contains non-ELF files (ld.so.cache is the usual one). They
    # have no symbols at all, which would otherwise be counted as "stripped".
    if ! readelf -h "$lib" >/dev/null 2>&1; then
        continue
    fi

    total=$((total + 1))

    # Local symbol count. `nm` without -D reads the full symbol table, which a
    # stripped library does not have; it fails rather than printing zero.
    all_syms="$(nm --defined-only "$lib" 2>/dev/null | wc -l || true)"
    [ -z "$all_syms" ] && all_syms=0

    build_id="$(readelf -n "$lib" 2>/dev/null | sed -n 's/.*Build ID: *\([0-9a-f]*\).*/\1/p' | head -1 || true)"
    debuglink="$(readelf -p .gnu_debuglink "$lib" 2>/dev/null | sed -n 's/^ *\[ *[0-9a-f]*\] *//p' | head -1 || true)"

    # Where a separate debug file would live, keyed by Build ID.
    debug_state="-"
    if [ "$all_syms" -eq 0 ]; then
        stripped=$((stripped + 1))
        want_debug=$((want_debug + 1))
        stripped_list="${stripped_list}${name}"$'\n'
        debug_state="MISSING"
        if [ -n "${DEBUG_DIR:-}" ] && [ -n "$build_id" ]; then
            candidate="${DEBUG_DIR}/.build-id/${build_id:0:2}/${build_id:2}.debug"
            if [ -f "$candidate" ]; then
                debug_state="found"
                have_debug=$((have_debug + 1))
            fi
        fi
        # A stripped library seldom has its own SysPart output; the exposure
        # is being a DT_NEEDED dependency of something that does, because the
        # analysis walks into it. Match on soname, which is the name the
        # depending library records.
        if [ -n "$SYSCALLS_DIR" ] && [ -d "$SYSCALLS_DIR" ]; then
            soname="$(readelf -d "$lib" 2>/dev/null | sed -n 's/.*soname *: *\[\(.*\)\].*/\1/p' || true)"
            [ -z "$soname" ] && soname="$name"
            for analysed in "$SYSCALLS_DIR"/*/; do
                [ -d "$analysed" ] || continue
                a_name="$(basename "$analysed")"
                a_lib="$(find "$LIBS_TARGET" -type f -name "$a_name" 2>/dev/null | head -1)"
                [ -n "$a_lib" ] || continue
                if readelf -d "$a_lib" 2>/dev/null | grep -q "Shared library: \[$soname\]"; then
                    stripped_analysed=$((stripped_analysed + 1))
                    reached_list="${reached_list}${name} (via ${a_name})
"
                    break
                fi
            done
        fi
    fi

    id_short="${build_id:0:10}"
    [ -z "$id_short" ] && id_short="-"
    syms_col="$all_syms"
    [ "$all_syms" -eq 0 ] && syms_col="STRIPPED"

    printf "%-34s %-14s %-12s %s\n" "$name" "$syms_col" "$id_short" "$debug_state"
done < <(find "$LIBS_TARGET" -type f -name "*.so*" 2>/dev/null | sort)

echo ""
echo "============================================================"
echo " Summary"
echo "============================================================"
echo "Libraries scanned:        $total"
echo "  with local symbols:     $((total - stripped))"
echo "  stripped:               $stripped"
if [ -n "${DEBUG_DIR:-}" ]; then
    echo "  separate debug found:   $have_debug of $want_debug stripped"
fi
if [ -n "$SYSCALLS_DIR" ] && [ -d "$SYSCALLS_DIR" ]; then
    echo "  reached by analysis:    $stripped_analysed  (dependency of an analysed library)"
fi

if [ "$stripped" -gt 0 ]; then
    echo ""
    echo "Stripped libraries:"
    printf '%s' "$stripped_list" | sed 's/^/  /'
    echo ""
    if [ -n "$reached_list" ]; then
        echo ""
        echo "Reached by analysed libraries:"
        printf '%s' "$reached_list" | sed 's/^/  /'
    fi
    echo ""
    echo "Indirect-call resolution inside these is degraded, so syscalls behind"
    echo "unresolved edges may be absent from the generated profile."
    if [ -z "${DEBUG_DIR:-}" ]; then
        echo "Point DEBUG_DIR at a debug store to check whether symbols are available:"
        echo "  DEBUG_DIR=/usr/lib/debug $0 $LIBS_TARGET"
    fi
fi

exit 0
