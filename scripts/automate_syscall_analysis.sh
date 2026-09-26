#!/bin/bash

#############################################################################
# Automated Syscall Analysis Script
#
# This script automates the process of analyzing ELF binaries for syscalls
# using .sh from SysPartCode.
#
# The script will:
#   1. Read start function files from the specified directory
#   2. Match each file to its corresponding binary in the LIBS directory
#   3. Run .sh from SysPartCode/analysis/app for each binary
#   4. Save results in organized output directories
#
# Usage: ./scripts/automate_syscall_analysis.sh [OPTIONS]
#
# Options:
#   --startfunc-dir <dir>    Directory containing start function files (default: ./outputs)
#   --binary-dir <dir>       Directory containing ELF library files (default: ./LIBS)
#   --binaries-dir <dir>     Directory containing executable binaries (auto-detected from --img-name)
#   --output-dir <dir>       Directory to store syscall results (default: ./syscalls_output)
#   --syspart-dir <dir>      SysPartCode installation directory (default: ../SysPartCode)
#   --img-name <suffix>      Image safe name suffix (e.g., 33f67c1a1642)
#   --log                    Enable logging (creates logfile.txt for each binary)
#   --help                   Show this help message
#
# Example:
#   ./automate_syscall_analysis.sh --log
#   ./automate_syscall_analysis.sh --startfunc-dir /path/to/outputs --binary-dir /path/to/libs
#############################################################################

# Default directories (relative to script location)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
STARTFUNC_DIR="$PROJECT_ROOT/outputs"
BINARY_DIR="$PROJECT_ROOT/LIBS"
BINARIES_DIR=""  # Will be auto-detected or set via --binaries-dir
OUTPUT_BASE_DIR="$PROJECT_ROOT/syscalls_output"
SYSPART_DIR="${SYSPART_DIR:-$PROJECT_ROOT/SysPartCode}"
ENABLE_LOG=""
IMG_NAME=""  # Image safe name suffix (e.g., 33f67c1a1642)
BINARIES_ONLY=""  # When set, skip library analysis and only process binaries

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

#############################################################################
# Function: build_user_library_path
# Description: Build USER_LIBRARY_PATH that includes BINARY_DIR and all
#   JDK<V>_LIBS subdirectories so ldd can resolve libjvm.so etc.
#   Handles both JDK 8 (amd64/server/) and JDK 9+ (server/) layouts.
# Arguments: $1 - base BINARY_DIR (e.g. LIBS_jetty_9.4.51)
# Returns: colon-separated path string via stdout
#############################################################################
build_user_library_path() {
    local base_dir="$1"
    local paths="$base_dir"

    # Find all JDK<V>_LIBS directories
    for jdk_dir in "$base_dir"/JDK*_LIBS; do
        [ -d "$jdk_dir" ] || continue
        paths="$paths:$jdk_dir"

        # Add all subdirectories that contain .so files
        while IFS= read -r subdir; do
            [ -n "$subdir" ] && paths="$paths:$subdir"
        done < <(find "$jdk_dir" -mindepth 1 -type d 2>/dev/null | sort)
    done

    echo "$paths"
}

#############################################################################
# Function: print_usage
# Description: Display usage information
#############################################################################
print_usage() {
    grep "^#" "$0" | grep -v "#!/bin/bash" | sed 's/^# //g' | sed 's/^#//g'
}

#############################################################################
# Function: log_message
# Description: Print colored log messages
# Arguments: $1 - message type (INFO/SUCCESS/WARNING/ERROR)
#            $2 - message text
#############################################################################
log_message() {
    local type="$1"
    local msg="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$type" in
        INFO)
            echo -e "${BLUE}[INFO]${NC} [$timestamp] $msg"
            ;;
        SUCCESS)
            echo -e "${GREEN}[SUCCESS]${NC} [$timestamp] $msg"
            ;;
        WARNING)
            echo -e "${YELLOW}[WARNING]${NC} [$timestamp] $msg"
            ;;
        ERROR)
            echo -e "${RED}[ERROR]${NC} [$timestamp] $msg"
            ;;
        *)
            echo "[$timestamp] $msg"
            ;;
    esac
}

#############################################################################
# Function: auto_detect_img_name
# Description: Auto-detect IMG_NAME suffix from directory names
#############################################################################
auto_detect_img_name() {
    # Try to detect from outputs_* directories
    local outputs_dirs=("$PROJECT_ROOT"/outputs_*)
    if [ -d "${outputs_dirs[0]}" ]; then
        local dir_name=$(basename "${outputs_dirs[0]}")
        IMG_NAME="${dir_name#outputs_}"
        log_message "INFO" "Auto-detected IMG_NAME: $IMG_NAME"
        return 0
    fi

    # Try to detect from BINARIES_* directories
    local binaries_dirs=("$PROJECT_ROOT"/BINARIES_*)
    if [ -d "${binaries_dirs[0]}" ]; then
        local dir_name=$(basename "${binaries_dirs[0]}")
        IMG_NAME="${dir_name#BINARIES_}"
        log_message "INFO" "Auto-detected IMG_NAME from BINARIES: $IMG_NAME"
        return 0
    fi

    return 1
}

#############################################################################
# Function: check_prerequisites
# Description: Verify all required directories and scripts exist
#############################################################################
check_prerequisites() {
    log_message "INFO" "Checking prerequisites..."

    # Auto-detect IMG_NAME if not set
    if [ -z "$IMG_NAME" ]; then
        auto_detect_img_name
        if [ $? -ne 0 ]; then
            log_message "WARNING" "Could not auto-detect IMG_NAME suffix"
        fi
    fi

    # Update directories based on IMG_NAME
    if [ -n "$IMG_NAME" ]; then
        if [[ "$STARTFUNC_DIR" == "$PROJECT_ROOT/outputs" ]]; then
            STARTFUNC_DIR="$PROJECT_ROOT/outputs_$IMG_NAME"
            log_message "INFO" "Using IMG_NAME-based startfunc dir: $STARTFUNC_DIR"
        fi
        if [[ "$BINARY_DIR" == "$PROJECT_ROOT/LIBS" ]]; then
            BINARY_DIR="$PROJECT_ROOT/LIBS_$IMG_NAME"
            log_message "INFO" "Using IMG_NAME-based library dir: $BINARY_DIR"
        fi
        if [ -z "$BINARIES_DIR" ]; then
            BINARIES_DIR="$PROJECT_ROOT/BINARIES_$IMG_NAME"
            log_message "INFO" "Using IMG_NAME-based binaries dir: $BINARIES_DIR"
        fi
        if [[ "$OUTPUT_BASE_DIR" == "$PROJECT_ROOT/syscalls_output" ]]; then
            OUTPUT_BASE_DIR="$PROJECT_ROOT/syscalls_output_$IMG_NAME"
            log_message "INFO" "Using IMG_NAME-based output dir for libraries: $OUTPUT_BASE_DIR"
        fi
    fi

    # Check if start function directory exists
    if [ ! -d "$STARTFUNC_DIR" ]; then
        log_message "ERROR" "Start function directory does not exist: $STARTFUNC_DIR"
        return 1
    fi

    # Check if binary directory exists
    if [ ! -d "$BINARY_DIR" ]; then
        log_message "ERROR" "Binary directory does not exist: $BINARY_DIR"
        return 1
    fi

    # Check if SysPartCode directory exists
    if [ ! -d "$SYSPART_DIR" ]; then
        log_message "ERROR" "SysPartCode directory does not exist: $SYSPART_DIR"
        return 1
    fi

    # Check if analysis/app directory exists
    if [ ! -d "$SYSPART_DIR/analysis/app" ]; then
        log_message "ERROR" "SysPartCode analysis/app directory does not exist: $SYSPART_DIR/analysis/app"
        return 1
    fi

    # Check if .sh exists (relative to analysis/app)
    local compute_script="$SYSPART_DIR/analysis/app/src/scripts/compute_syscalls.sh"
    if [ ! -f "$compute_script" ]; then
        log_message "ERROR" "compute_syscalls.sh not found: $compute_script"
        return 1
    fi

    # Check if compute_syscalls.sh.sh is executable
    if [ ! -x "$compute_script" ]; then
        log_message "WARNING" "compute_syscalls.sh.sh is not executable, attempting to set execute permission..."
        chmod +x "$compute_script" 2>/dev/null
        if [ $? -ne 0 ]; then
            log_message "ERROR" "Failed to set execute permission on compute_syscalls.sh"
            return 1
        fi
    fi

    log_message "SUCCESS" "All prerequisites satisfied"
    return 0
}

#############################################################################
# Function: create_output_directory
# Description: Create output directory structure
# Arguments: $1 - library name (without .txt extension)
#############################################################################
create_output_directory() {
    local lib_name="$1"
    local output_dir="$OUTPUT_BASE_DIR/$lib_name"

    if [ ! -d "$output_dir" ]; then
        mkdir -p "$output_dir"
        if [ $? -ne 0 ]; then
            log_message "ERROR" "Failed to create output directory: $output_dir"
            return 1
        fi
    fi

    echo "$output_dir"
    return 0
}

#############################################################################
# Function: find_binary_file
# Description: Find the corresponding binary file for a start function file
# Arguments: $1 - start function filename (e.g., libjava.so.txt or 1libjava.so.txt)
# Returns: Path to binary file or empty string if not found
#############################################################################
find_binary_file() {
    local startfunc_file="$1"
    local binary_name=""

    # Remove .txt extension
    binary_name="${startfunc_file%.txt}"

    # Remove leading numbers (e.g., 1libjava.so -> libjava.so)
    binary_name=$(echo "$binary_name" | sed 's/^[0-9]*//g')

    # If startfunc_file is an absolute path or contains the STARTFUNC_DIR prefix,
    # derive the relative subpath so we can look for subdirectories
    # (e.g. JDK8_LIBS/amd64/libnet.so under BINARY_DIR).
    local rel_path="$binary_name"
    if [[ -n "${STARTFUNC_DIR:-}" && "$startfunc_file" == "$STARTFUNC_DIR"/* ]]; then
        # Strip STARTFUNC_DIR prefix and .txt suffix to get relative binary path
        rel_path="${startfunc_file#$STARTFUNC_DIR/}"
        rel_path="${rel_path%.txt}"
    fi

    # Try relative subpath first (e.g. BINARY_DIR/JDK8_LIBS/amd64/libnet.so)
    local binary_path="$BINARY_DIR/$rel_path"
    if [ -f "$binary_path" ]; then
        echo "$binary_path"
        return 0
    fi

    # Fallback: try flat basename (e.g. BINARY_DIR/libnet.so)
    local flat_name
    flat_name=$(basename "$binary_name")
    binary_path="$BINARY_DIR/$flat_name"
    if [ -f "$binary_path" ]; then
        echo "$binary_path"
        return 0
    fi

    log_message "WARNING" "Binary not found: $BINARY_DIR/$rel_path"
    return 1
}

#############################################################################
# Function: create_binary_start_file
# Description: Create a start.txt file for a binary
#              - First checks if "_start" symbol exists
#              - If not, extracts imported (UND) functions from objdump -T
# Arguments: $1 - output directory for the binary
#            $2 - path to the binary file
# Returns: Path to created start.txt file
#############################################################################
create_binary_start_file() {
    local output_dir="$1"
    local binary_path="$2"
    local start_file="$output_dir/start.txt"
    local binary_name=$(basename "$binary_path")

    # Check if binary has _start symbol
    log_message "INFO" "Checking for _start symbol in: $binary_name" >&2

    # Try nm with regular symbols first
    if nm "$binary_path" 2>/dev/null | grep -q " [Tt] _start$"; then
        log_message "INFO" "Found _start symbol (nm), using it as entry point" >&2
        echo "_start" > "$start_file"
    # Try nm with dynamic symbols (-D flag)
    elif nm -D "$binary_path" 2>/dev/null | grep -q " [Tt] _start$"; then
        log_message "INFO" "Found _start symbol (nm -D), using it as entry point" >&2
        echo "_start" > "$start_file"
    # Try objdump as fallback
    elif objdump -t "$binary_path" 2>/dev/null | grep -q " _start$"; then
        log_message "INFO" "Found _start symbol (objdump), using it as entry point" >&2
        echo "_start" > "$start_file"
    else
        log_message "WARN" "No _start symbol found in: $binary_name" >&2
        log_message "INFO" "Extracting imported (UND) functions as start functions" >&2

        # Extract imported functions using objdump -T
        # Filter for UND (undefined/imported) symbols and extract function names
        local imported_funcs=$(objdump -T "$binary_path" 2>/dev/null | \
                              awk '/UND/ { print $NF }' | \
                              grep -v "^_ITM_" | \
                              grep -v "^__gmon_start__" | \
                              grep -v "^__cxa_" | \
                              grep -v "^$" | \
                              sort -u)

        if [ -z "$imported_funcs" ]; then
            log_message "ERROR" "Could not extract any imported functions from: $binary_name" >&2
            log_message "ERROR" "Binary may be stripped or statically linked" >&2
            # Create file with _start anyway as fallback
            echo "_start" > "$start_file"
            log_message "WARN" "Created start file with _start (may fail during analysis)" >&2
        else
            echo "$imported_funcs" > "$start_file"
            local func_count=$(echo "$imported_funcs" | wc -l)
            log_message "SUCCESS" "Extracted $func_count imported functions as start functions" >&2
            log_message "INFO" "Sample functions: $(echo "$imported_funcs" | head -3 | tr '\n' ' ' | sed 's/ $/.../')" >&2
        fi
    fi

    if [ ! -f "$start_file" ] || [ ! -s "$start_file" ]; then
        log_message "ERROR" "Failed to create non-empty start file: $start_file" >&2
        return 1
    fi

    echo "$start_file"
    return 0
}

#############################################################################
# Function: process_binary
# Description: Process a single executable binary and run syscall analysis
# Arguments: $1 - path to binary file
#############################################################################
process_binary() {
    local binary_path="$1"
    local binary_basename=$(basename "$binary_path")

    log_message "INFO" "Processing binary: $binary_basename"

    # Create output directory for this binary
    local output_dir="$OUTPUT_BASE_DIR/$binary_basename"
    mkdir -p "$output_dir"
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Failed to create output directory: $output_dir"
        return 1
    fi

    log_message "INFO" "Output directory: $output_dir"

    #########################################################################
    # Step 1: Create start function file
    #########################################################################
    log_message "INFO" "Step 1/3: Creating start function file..."
    local start_file="$output_dir/start.txt"

    # Check for _start symbol
    if nm "$binary_path" 2>/dev/null | grep -q " [Tt] _start$"; then
        echo "_start" > "$start_file"
        log_message "SUCCESS" "Found _start symbol, using it as entry point"
    elif nm -D "$binary_path" 2>/dev/null | grep -q " [Tt] _start$"; then
        echo "_start" > "$start_file"
        log_message "SUCCESS" "Found _start symbol (dynamic), using it as entry point"
    else
        log_message "WARNING" "No _start symbol found, extracting imported functions..."

        # Extract imported (UND) functions
        objdump -T "$binary_path" 2>/dev/null | \
            awk '/UND/ { print $NF }' | \
            grep -v "^_ITM_" | \
            grep -v "^__gmon_start__" | \
            grep -v "^__cxa_" | \
            grep -v "^$" | \
            sort -u > "$start_file"

        local func_count=$(wc -l < "$start_file")
        if [ "$func_count" -eq 0 ]; then
            log_message "ERROR" "Could not extract any start functions from: $binary_basename"
            return 1
        fi

        log_message "SUCCESS" "Extracted $func_count imported functions as start points"
    fi

    #########################################################################
    # Step 2: Run SysPart analysis
    #########################################################################
    log_message "INFO" "Step 2/3: Running SysPart syscall analysis..."

    # Change to SysPartCode/analysis/app directory
    local syspart_app_dir="$SYSPART_DIR/analysis/app"
    if [ ! -d "$syspart_app_dir" ]; then
        log_message "ERROR" "SysPartCode analysis/app directory does not exist: $syspart_app_dir"
        return 1
    fi

    pushd "$syspart_app_dir" > /dev/null

    # Run compute_syscalls.sh with USER_LIBRARY_PATH set
    local compute_script="src/scripts/compute_syscalls.sh"
    if [ ! -f "$compute_script" ]; then
        log_message "ERROR" "compute_syscalls.sh not found at: $compute_script (pwd: $(pwd))"
        popd > /dev/null
        return 1
    fi

    local lib_path
    lib_path=$(build_user_library_path "$BINARY_DIR")

    log_message "INFO" "Executing command:"
    echo "    cd $syspart_app_dir"
    echo "    USER_LIBRARY_PATH=\"$lib_path\" \\"
    echo "      $compute_script \\"
    echo "      \"$binary_path\" \\"
    echo "      \"$output_dir\" \\"
    echo "      \"$start_file\" \\"
    echo "      --log"
    echo ""

    USER_LIBRARY_PATH="$lib_path" $compute_script \
        "$binary_path" \
        "$output_dir" \
        "$start_file" \
        --log \
        2>&1 | tee -a "$output_dir/logfile.txt"

    local syspart_exit=${PIPESTATUS[0]}

    popd > /dev/null

    if [ $syspart_exit -ne 0 ]; then
        log_message "ERROR" "SysPart analysis failed (exit code: $syspart_exit)"
        log_message "ERROR" "Check log file: $output_dir/logfile.txt"
        return 1
    fi

    #########################################################################
    # Step 3: Verify and report results
    #########################################################################
    log_message "INFO" "Step 3/3: Verifying results..."

    if [ ! -f "$output_dir/syscalls.txt" ]; then
        log_message "ERROR" "No syscalls.txt generated"
        log_message "ERROR" "Check log file: $output_dir/logfile.txt"
        return 1
    fi

    local syscall_count=$(wc -l < "$output_dir/syscalls.txt")

    if [ "$syscall_count" -eq 0 ]; then
        log_message "WARNING" "syscalls.txt is empty (no syscalls found)"
    else
        log_message "SUCCESS" "Found $syscall_count syscalls"
    fi

    # List generated files
    log_message "INFO" "Generated files:"
    for file in syscalls.txt callgraph.json allfunctions.txt startfuncs_with_addr.txt; do
        if [ -f "$output_dir/$file" ]; then
            local size=$(wc -l < "$output_dir/$file" 2>/dev/null || echo "N/A")
            log_message "INFO" "  - $file ($size lines)"
        fi
    done

    log_message "SUCCESS" "Completed analysis for binary: $binary_basename"
    return 0
}

#############################################################################
# Function: process_library
# Description: Process a single library and run syscall analysis
# Arguments: $1 - start function file path
#############################################################################
process_library() {
    local startfunc_file="$1"
    local startfunc_basename=$(basename "$startfunc_file")
    local lib_name="${startfunc_basename%.txt}"

    log_message "INFO" "Processing: $startfunc_file"

    # Find corresponding binary (pass full path so subdir structure is preserved)
    local binary_path=$(find_binary_file "$startfunc_file")
    if [ -z "$binary_path" ]; then
        log_message "ERROR" "Could not find binary for: $startfunc_file"
        return 1
    fi

    log_message "INFO" "Found binary: $binary_path"

    # Create output directory for this library
    local output_dir=$(create_output_directory "$lib_name")
    if [ $? -ne 0 ]; then
        return 1
    fi

    log_message "INFO" "Output directory: $output_dir"

    # Change to SysPartCode/analysis/app directory
    local syspart_app_dir="$SYSPART_DIR/analysis/app"
    if [ ! -d "$syspart_app_dir" ]; then
        log_message "ERROR" "SysPartCode analysis/app directory does not exist: $syspart_app_dir"
        return 1
    fi

    pushd "$syspart_app_dir" > /dev/null

    # Run compute_syscalls.sh.sh (path relative to analysis/app)
    local compute_script="src/scripts/compute_syscalls.sh"
    if [ ! -f "$compute_script" ]; then
        log_message "ERROR" " not found at: $compute_script (pwd: $(pwd))"
        popd > /dev/null
        return 1
    fi

    # Build USER_LIBRARY_PATH including JDK lib subdirectories
    # so ldd can resolve libjvm.so, libjava.so, etc.
    local lib_path
    lib_path=$(build_user_library_path "$BINARY_DIR")

    local cmd="USER_LIBRARY_PATH=\"$lib_path\" $compute_script \"$binary_path\" \"$output_dir\" \"$startfunc_file\""

    if [ -n "$ENABLE_LOG" ]; then
        cmd="$cmd --log"
    fi

    log_message "INFO" "Executing from: $syspart_app_dir"
    log_message "INFO" "USER_LIBRARY_PATH=$lib_path"
    log_message "INFO" "Command: $cmd"

    eval $cmd
    local exit_code=$?

    popd > /dev/null

    if [ $exit_code -eq 0 ]; then
        log_message "SUCCESS" "Completed analysis for: $startfunc_basename"
        return 0
    else
        log_message "ERROR" "Failed to analyze: $startfunc_basename (exit code: $exit_code)"
        return 1
    fi
}

#############################################################################
# Function: main
# Description: Main execution function
#############################################################################
main() {
    log_message "INFO" "=== Automated Syscall Analysis ==="
    log_message "INFO" "Start function directory: $STARTFUNC_DIR"
    log_message "INFO" "Library directory: $BINARY_DIR"
    log_message "INFO" "Binaries directory: ${BINARIES_DIR:-Not set}"
    log_message "INFO" "Output base directory: $OUTPUT_BASE_DIR"
    log_message "INFO" "SysPartCode directory: $SYSPART_DIR"
    log_message "INFO" "IMG_NAME suffix: ${IMG_NAME:-Not set}"
    log_message "INFO" "Logging enabled: $([ -n "$ENABLE_LOG" ] && echo "Yes" || echo "No")"
    echo ""

    # Check prerequisites
    check_prerequisites
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Prerequisites check failed. Exiting."
        exit 1
    fi

    # Create base output directory
    mkdir -p "$OUTPUT_BASE_DIR"
    if [ $? -ne 0 ]; then
        log_message "ERROR" "Failed to create base output directory: $OUTPUT_BASE_DIR"
        exit 1
    fi

    local total_files=0
    local success_count=0
    local failure_count=0

    if [ -n "$BINARIES_ONLY" ]; then
        log_message "INFO" "Skipping library analysis (--binaries-only)"
    else
        # Find all start function files (including subdirectories like JDK8_LIBS/amd64/)
        local startfunc_files=()
        while IFS= read -r f; do
            startfunc_files+=("$f")
        done < <(find "$STARTFUNC_DIR" \( -name "*.so.txt" -o -name "*.so.[0-9]*.txt" \) -type f | sort)

        if [ ${#startfunc_files[@]} -eq 0 ]; then
            log_message "ERROR" "No start function files found in: $STARTFUNC_DIR"
            exit 1
        fi

        total_files=${#startfunc_files[@]}
        log_message "INFO" "Found $total_files start function files to process"
        echo ""

        # Process each library
        local current=0

        for startfunc_file in "${startfunc_files[@]}"; do
            current=$((current + 1))

            # Skip non-library files (e.g., filtered_method_syscalls.txt, mapped_method_syscalls.txt)
            local sf_basename=$(basename "$startfunc_file")
            if [[ "$sf_basename" != *.so.txt && "$sf_basename" != *.so.[0-9]*.txt ]]; then
                log_message "INFO" "[$current/$total_files] Skipping non-library file: $sf_basename"
                total_files=$((total_files - 1))
                continue
            fi

            echo ""
            log_message "INFO" "[$current/$total_files] ======================================"

            process_library "$startfunc_file"
            if [ $? -eq 0 ]; then
                success_count=$((success_count + 1))
            else
                failure_count=$((failure_count + 1))
            fi
        done
    fi

    # Process binaries if BINARIES_DIR exists and is set
    if [ -n "$BINARIES_DIR" ] && [ -d "$BINARIES_DIR" ]; then
        echo ""
        echo ""
        log_message "INFO" "=== Processing Executable Binaries ==="
        log_message "INFO" "Binaries directory: $BINARIES_DIR"

        # Create separate output directory for binaries
        local BINARY_OUTPUT_DIR="$PROJECT_ROOT/syscalls_BIN_$IMG_NAME"
        if [ -z "$IMG_NAME" ]; then
            BINARY_OUTPUT_DIR="$PROJECT_ROOT/syscalls_binaries"
        fi

        mkdir -p "$BINARY_OUTPUT_DIR"
        log_message "INFO" "Binaries output directory: $BINARY_OUTPUT_DIR"
        echo ""

        # Temporarily save library output dir and switch to binary output dir
        local SAVED_OUTPUT_BASE_DIR="$OUTPUT_BASE_DIR"
        OUTPUT_BASE_DIR="$BINARY_OUTPUT_DIR"

        # Find all executable binaries
        local binary_files=()
        while IFS= read -r -d '' binary_file; do
            binary_files+=("$binary_file")
        done < <(find "$BINARIES_DIR" -maxdepth 1 -type f -executable -print0)

        if [ ${#binary_files[@]} -eq 0 ]; then
            log_message "WARNING" "No executable binaries found in: $BINARIES_DIR"
        else
            local total_binaries=${#binary_files[@]}
            log_message "INFO" "Found $total_binaries executable binaries to process"
            echo ""

            local binary_current=0
            for binary_file in "${binary_files[@]}"; do
                binary_current=$((binary_current + 1))
                echo ""
                log_message "INFO" "[$binary_current/$total_binaries] ======================================"

                process_binary "$binary_file"
                if [ $? -eq 0 ]; then
                    success_count=$((success_count + 1))
                    total_files=$((total_files + 1))
                else
                    failure_count=$((failure_count + 1))
                    total_files=$((total_files + 1))
                fi
            done
        fi

        # Restore library output dir
        OUTPUT_BASE_DIR="$SAVED_OUTPUT_BASE_DIR"
    else
        log_message "INFO" "Binaries directory not set or does not exist, skipping binary analysis"
    fi

    # Summary
    echo ""
    log_message "INFO" "=== Analysis Summary ==="
    log_message "INFO" "Total files processed: $total_files"
    log_message "SUCCESS" "Successful: $success_count"
    if [ $failure_count -gt 0 ]; then
        log_message "ERROR" "Failed: $failure_count"
    else
        log_message "INFO" "Failed: $failure_count"
    fi
    log_message "INFO" "Libraries results saved to: $OUTPUT_BASE_DIR"
    if [ -n "$BINARIES_DIR" ] && [ -d "$BINARIES_DIR" ]; then
        local BINARY_OUTPUT_DIR="$PROJECT_ROOT/syscalls_BIN_$IMG_NAME"
        if [ -z "$IMG_NAME" ]; then
            BINARY_OUTPUT_DIR="$PROJECT_ROOT/syscalls_binaries"
        fi
        log_message "INFO" "Binaries results saved to: $BINARY_OUTPUT_DIR"
    fi

    #########################################################################
    # Merge syscalls and generate seccomp profile
    #########################################################################
    if [ -n "$IMG_NAME" ]; then
        echo ""
        echo ""
        log_message "INFO" "=== Merging Syscalls and Generating Seccomp Profile ==="

        local merge_script="$SCRIPT_DIR/merge_all_syscalls.py"
        if [ ! -f "$merge_script" ]; then
            log_message "WARNING" "merge_all_syscalls.py not found at: $merge_script"
            log_message "WARNING" "Skipping syscall merge and seccomp profile generation"
        else
            log_message "INFO" "Running: python3 merge_all_syscalls.py $IMG_NAME"
            echo ""

            python3 "$merge_script" "$IMG_NAME"
            local merge_exit=$?

            echo ""
            if [ $merge_exit -eq 0 ]; then
                log_message "SUCCESS" "Syscall merge and seccomp profile generation completed"
                log_message "INFO" "Seccomp profile: $PROJECT_ROOT/syscalls_output_$IMG_NAME/${IMG_NAME}.json"
            else
                log_message "ERROR" "Syscall merge failed (exit code: $merge_exit)"
                log_message "WARNING" "Analysis results are still available in output directories"
            fi
        fi
    else
        log_message "INFO" "IMG_NAME not set, skipping syscall merge and seccomp profile generation"
    fi

    if [ $failure_count -gt 0 ]; then
        exit 1
    else
        exit 0
    fi
}

#############################################################################
# Parse command line arguments
#############################################################################
while [[ $# -gt 0 ]]; do
    case $1 in
        --startfunc-dir)
            STARTFUNC_DIR="$2"
            shift 2
            ;;
        --binary-dir)
            BINARY_DIR="$2"
            shift 2
            ;;
        --binaries-dir)
            BINARIES_DIR="$2"
            shift 2
            ;;
        --output-dir)
            OUTPUT_BASE_DIR="$2"
            shift 2
            ;;
        --syspart-dir)
            SYSPART_DIR="$2"
            shift 2
            ;;
        --img-name)
            IMG_NAME="$2"
            shift 2
            ;;
        --log)
            ENABLE_LOG="--log"
            shift
            ;;
        --binaries-only)
            BINARIES_ONLY="1"
            shift
            ;;
        --help)
            print_usage
            exit 0
            ;;
        *)
            log_message "ERROR" "Unknown option: $1"
            echo ""
            print_usage
            exit 1
            ;;
    esac
done

# Run main function
main
