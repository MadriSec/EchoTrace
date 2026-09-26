#!/bin/bash
set -e  # stop if any command fails

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
#IMG_NAME=cassandra_3.0.29 \
#LIBS_DIR=${SCRIPT_DIR}/LIBS_cassandra_3.0.29 \
#  bash run_analysis.sh
ANALYSIS_MODE="${ANALYSIS_MODE:-FULL_BYTECODE}"

# IMG_NAME is required — all per-image directories derive from it
if [ -z "${IMG_NAME:-}" ]; then
    echo "ERROR: IMG_NAME is required. Example: IMG_NAME=cassandra_3.0.29 bash run_analysis.sh"
    exit 1
fi

LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-${PROJECT_ROOT}/LIBS_${IMG_NAME}}}"
OUTPUTS_BASE_DIR="${OUTPUTS_DIR:-${PROJECT_ROOT}/outputs_${IMG_NAME}}"
RUNTIME_BASE_DIR="${RUNTIME_DIR:-${PROJECT_ROOT}/RUNTIME_${IMG_NAME}}"
mkdir -p "$OUTPUTS_BASE_DIR"

if [ "$ANALYSIS_MODE" = "FULL_BYTECODE" ]; then
    # Check if we should skip bytecode analysis and go directly to mapper
    if [ "${SKIP_BYTECODE_ANALYSIS:-0}" = "1" ]; then
        echo "============================================================"
        echo " STEP 1: SKIPPED (SKIP_BYTECODE_ANALYSIS=1)"
        echo "============================================================"
        echo "Skipping SOOTUP bytecode analysis, using existing native_methods.txt"
    else
        echo "============================================================"
        echo " STEP 1: Running bytecode analysis"
        echo "============================================================"
        JAR_BASE_DIR="${JARFILES_DIR:-${PROJECT_ROOT}/JARFILES_${IMG_NAME}}"

        BYTECODE_MODE="${BYTECODE_MODE:-1}"
        echo "Bytecode analysis mode: $BYTECODE_MODE"

        if [ "$BYTECODE_MODE" = "2" ]; then
            echo "Running FinalPrototype (start from main)..."
            java -cp "${PROJECT_ROOT}/target/echotrace-1.0-SNAPSHOT.jar:${PROJECT_ROOT}/target/deps/*" \
              com.echotrace.app.bytecode_new.FinalPrototype \
              "${JAR_BASE_DIR}" \
              "${JAR_BASE_DIR}" \
              --1
        else
            echo "Running JNADetector (JNA/JNR/FFI + all native methods)..."
            mvn -f "${PROJECT_ROOT}/pom.xml" -q clean compile exec:java \
              -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
              -Dexec.args="${JAR_BASE_DIR} ${OUTPUTS_BASE_DIR} ${RUNTIME_BASE_DIR}"
        fi
    fi

    # echo "============================================================"
    # echo " STEP 2: Running formatter.py"
    # echo "============================================================"
    # python3 ${SCRIPT_DIR}/formatter.py

    echo "============================================================"
    echo " STEP 2: Native mapping and start-function preparation"
    echo "============================================================"
    LIBS_IMAGE="${LIBS_BASE_DIR}" OUTPUTS_DIR="${OUTPUTS_BASE_DIR}" \
      bash "${SCRIPT_DIR}/prepare_native_mapping.sh"
    echo "============================================================"
    echo " Analysis pipeline completed!"
    echo "============================================================"

else
    echo "============================================================"
    echo " Bytecode analysis skipped (Mode: $ANALYSIS_MODE)"
    echo "============================================================"
    echo "Using symbol-based analysis instead of bytecode analysis"
    echo "Starting function file will be used directly for syscall analysis"
    echo "============================================================"
fi
echo "============================================================"
echo " STEP 5: Running binary_analysis"
echo "============================================================"

LIBS_BASE_DIR="${LIBS_IMAGE:-${LIBS_DIR:-${PROJECT_ROOT}/LIBS_${IMG_NAME}}}"
STARTFUNCS_DIR="${OUTPUTS_DIR:-${PROJECT_ROOT}/outputs_${IMG_NAME}}"
SYSCALLS_OUT_DIR="${SYSCALLS_OUTPUT_DIR:-${PROJECT_ROOT}/syscalls_output_${IMG_NAME}}"
BINARIES_BASE_DIR="${BINARIES_DIR:-${PROJECT_ROOT}/BINARIES_${IMG_NAME}}"

# Determine which binaries to analyze based on mode
if [ "$ANALYSIS_MODE" = "FULL_BYTECODE" ]; then
    # Standard flow: analyze libraries based on mapper.py output
    echo "Analyzing libraries with mapped native methods..."
    bash "${SCRIPT_DIR}/automate_syscall_analysis.sh" \
      --binary-dir "${LIBS_BASE_DIR}" \
      --binaries-dir "${BINARIES_BASE_DIR}" \
      --startfunc-dir "${STARTFUNCS_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-name "${IMG_NAME}" \
      --log

elif [ "$ANALYSIS_MODE" = "LIBRARY_SYMBOLS" ]; then
    # Analyze libraries using extracted exported symbols
    echo "Analyzing libraries with exported symbols..."

    # Create startfunc files for each library based on exported symbols
    mkdir -p "$STARTFUNCS_DIR"

    for lib in "$LIBS_BASE_DIR"/*.so*; do
        [ -f "$lib" ] || continue
        lib_name=$(basename "$lib")
        startfunc_file="$STARTFUNCS_DIR/${lib_name}.txt"

        echo "  Creating startfunc file for: $lib_name"

        # Check if library is stripped
        if file "$lib" | grep -q "stripped"; then
            echo "    Library is stripped"

            # For stripped libraries, try to extract entry point (if it exists)
            entry_point=$(readelf -h "$lib" 2>/dev/null | awk '/Entry point/ {print $4}')

            if [ -n "$entry_point" ] && [ "$entry_point" != "0x0" ]; then
                echo "$entry_point" > "$startfunc_file"
                echo "    Using entry point address: $entry_point"
            else
                # No entry point (typical for .so files) - use exported dynamic symbols
                nm -D --defined-only "$lib" 2>/dev/null | \
                    awk '$2 == "T" || $2 == "W" {print $3}' | \
                    grep -v '^_' | \
                    sort -u > "$startfunc_file"

                sym_count=$(wc -l < "$startfunc_file")
                echo "    Extracted $sym_count exported symbols"
            fi
        else
            echo "    Library is not stripped"

            # Extract exported symbols for this library
            nm -D --defined-only "$lib" 2>/dev/null | \
                awk '$2 == "T" || $2 == "W" {print $3}' | \
                grep -v '^_' | \
                sort -u > "$startfunc_file"

            sym_count=$(wc -l < "$startfunc_file")
            echo "    Extracted $sym_count symbols"
        fi
    done

    bash "${SCRIPT_DIR}/automate_syscall_analysis.sh" \
      --binary-dir "${LIBS_BASE_DIR}" \
      --binaries-dir "${BINARIES_BASE_DIR}" \
      --startfunc-dir "${STARTFUNCS_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-name "${IMG_NAME}" \
      --log

elif [ "$ANALYSIS_MODE" = "BINARY_ONLY" ]; then
    # Analyze only executables using their entry points
    echo "Analyzing executables only (skipping .so libraries)..."

    # automate_syscall_analysis.sh handles binary start function generation
    # internally via create_binary_start_file. We just pass --binaries-dir
    # and --binaries-only to skip .so processing.
    bash "${SCRIPT_DIR}/automate_syscall_analysis.sh" \
      --binary-dir "${LIBS_BASE_DIR}" \
      --binaries-dir "${BINARIES_BASE_DIR}" \
      --output-dir "${SYSCALLS_OUT_DIR}" \
      --img-name "${IMG_NAME}" \
      --binaries-only \
      --log
fi

echo "============================================================"
echo " Binary analysis completed!"
echo "============================================================"
echo " STEP 6: Running combine_syscalls.sh"
# bash "${SCRIPT_DIR}/combine_syscalls.sh "${SYSCALLS_OUT_DIR}"
echo "============================================================"

# =============================================================================
# STEP 7: Unanalysed dynamically loaded libraries
# =============================================================================
# Libraries the container loads at runtime that no Java native binding reaches
# are invisible to the bytecode-driven pipeline. Skipping them leaves their
# syscalls out of the profile, and a syscall missing from a default-deny
# profile is a SIGSYS at runtime -- so this runs as part of every analysis.
#
# It is slower than the main analysis, since SysPart is run over every exported
# function of each unmapped library. Set ANALYZE_UNANALYSED=0 to skip it when
# iterating on an earlier stage; the resulting profile is then incomplete.
if [ "${ANALYZE_UNANALYSED:-1}" != "0" ]; then
    echo "============================================================"
    echo " STEP 7: Analysing unanalysed dynamically loaded libraries"
    echo "============================================================"

    IMG_NAME="${IMG_NAME}" python3 "${SCRIPT_DIR}/report_dynamic_leftover_after_analyzed_ldd.py" \
      --libs-dir "${LIBS_BASE_DIR}" \
      --syscalls-dir "${SYSCALLS_OUT_DIR}"

    IMG_NAME="${IMG_NAME}" python3 "${SCRIPT_DIR}/analyze_unanalysed_loaded_libs.py" \
      --libs-dir "${LIBS_BASE_DIR}" \
      --run-syspart

    echo "============================================================"
    echo " Unanalysed library analysis completed!"
    echo "============================================================"
else
    echo "============================================================"
    echo " STEP 7: SKIPPED (ANALYZE_UNANALYSED=0)"
    echo "============================================================"
    echo "Dynamically loaded libraries with no Java binding were not analysed."
    echo "Syscalls reachable only from those libraries are missing from the"
    echo "generated profile, which may cause SIGSYS at runtime."
fi

# =============================================================================
# STEP 8: JNA / jnr-ffi / FFM bindings
# =============================================================================
# The bytecode detectors resolve these bindings to a (library, symbol) pair,
# but the mapper only consumes native_methods.txt -- the plain `native`-keyword
# scan -- so those symbols were never seeded as SysPart entry points and no
# syscall reachable only through them entered the profile.
#
# Runs SysPart over each bound library using its bound symbols as start
# functions, and writes jna_ffi_analysis/union_syscalls.txt, which
# merge_all_syscalls.py reads. Set ANALYZE_JNA_FFI=0 to skip; the resulting
# profile then omits whatever those bindings reach.
if [ "${ANALYZE_JNA_FFI:-1}" != "0" ]; then
    echo "============================================================"
    echo " STEP 8: Analysing JNA / jnr-ffi / FFM bindings"
    echo "============================================================"

    IMG_NAME="${IMG_NAME}" python3 "${SCRIPT_DIR}/analyse_jna_ffi.py" \
      --libs-dir "${LIBS_BASE_DIR}" \
      --outputs-dir "${STARTFUNCS_DIR}" \
      --run-syspart

    echo "============================================================"
    echo " JNA/FFI binding analysis completed!"
    echo "============================================================"
else
    echo "============================================================"
    echo " STEP 8: SKIPPED (ANALYZE_JNA_FFI=0)"
    echo "============================================================"
    echo "JNA, jnr-ffi and FFM bindings were not analysed. Syscalls reachable"
    echo "only through those bindings are missing from the generated profile."
fi
