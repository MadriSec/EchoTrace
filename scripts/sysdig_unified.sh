#!/bin/bash
#############################################################################
# Script: sysdig_unified.sh
# Description: Unified sysdig capture for libraries, binaries, and JARs
#
# This script captures:
#   - Native libraries (.so files) via open/openat/openat2/mmap
#   - Executables via execve
#   - JAR files via open/openat/openat2
#
# All captured in one sysdig session for efficiency
#
# Usage: ./scripts/sysdig_unified.sh <container_id> [duration_seconds]
#############################################################################

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONTAINER_ID="$1"
DURATION="${2:-120}"

if [ -z "$CONTAINER_ID" ]; then
    echo "ERROR: Container ID required"
    echo "Usage: $0 <container_id> [duration_seconds]"
    echo ""
    echo "Example:"
    echo "  $0 elasticsearch 120"
    exit 1
fi

# Get container metadata
CNAME=$(docker inspect -f '{{.Name}}' "$CONTAINER_ID" 2>/dev/null | sed 's/^\///' || echo "$CONTAINER_ID")
CONTPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_ID" 2>/dev/null)
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CNAME")
IMG_NAME=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║          Unified Sysdig Capture - All Resources             ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Container Name: $CNAME"
echo "Container ID:   $CONTAINER_ID"
echo "Container PID:  $CONTPID"
echo "Image:          $IMG_RAW"
echo "IMG_NAME:       $IMG_NAME"
echo "Duration:       ${DURATION}s"
echo ""

# Create output directory for sysdig dynamic analysis
SYSDIG_OUTPUT_DIR="${PROJECT_ROOT}/sysdig_outputs_${IMG_NAME}"
mkdir -p "$SYSDIG_OUTPUT_DIR"

# Output files
RAW_OUTPUT="$SYSDIG_OUTPUT_DIR/raw_capture.txt"
LIBS_OUTPUT="$SYSDIG_OUTPUT_DIR/libs_loaded_raw.txt"
BINARIES_OUTPUT="$SYSDIG_OUTPUT_DIR/binaries_${IMG_NAME}.txt"
JARS_OUTPUT="$SYSDIG_OUTPUT_DIR/jars_${IMG_NAME}.txt"

echo "Output directory: $SYSDIG_OUTPUT_DIR"
echo ""

# --- STEP 1: Stop container for clean restart ---
echo "[1/5] Stopping container for clean restart..."
docker stop "$CNAME" 2>/dev/null || true
sleep 2

# --- STEP 2: Start unified sysdig monitoring ---
echo "[2/5] Starting unified sysdig capture..."
echo "      Monitoring events: open, openat, openat2, mmap, execve"
echo ""

# Capture 1: Libraries (.so) and JARs (.jar)
# Using timeout instead of -M flag due to issues with --modern-bpf
# Filter: evt.failed=false to only capture successful opens
timeout "$DURATION" sudo sysdig --modern-bpf \
  "container.name=$CNAME and evt.type in (open,openat,openat2,mmap) and evt.failed=false and (fd.name contains .so or fd.name contains .jar)" \
  -p "%evt.time %evt.type %proc.pid %proc.name %fd.name %fd.typechar" \
  > "$RAW_OUTPUT" 2>"${RAW_OUTPUT}.err" &

SYSDIG_PID=$!
echo "      Sysdig PID (libs/jars): $SYSDIG_PID"

# Capture 2: Binary executions
# Note: execve doesn't have reliable exit events since it replaces the process
# Capture both directions to ensure we catch all execve calls
timeout "$DURATION" sudo sysdig --modern-bpf \
  "container.name=$CNAME and evt.type=execve" \
  -p "%evt.time %evt.type %proc.name %proc.exe" \
  > "${RAW_OUTPUT}.execve" 2>"${RAW_OUTPUT}.execve.err" &

SYSDIG_EXEC_PID=$!
echo "      Sysdig PID (execve):    $SYSDIG_EXEC_PID"

# Wait for sysdig BPF probes to fully attach before starting the container.
# --modern-bpf needs time to compile and load BPF programs; 2s is too short
# and causes missed events during JVM startup (the most critical window).
echo "      Waiting for sysdig to initialize (5s)..."
sleep 5

# Verify both sysdig processes are running
SYSDIG_OK=true
for i in {1..5}; do
    if ! kill -0 $SYSDIG_PID 2>/dev/null; then
        if [ $i -eq 5 ]; then
            echo "      ✗ ERROR: sysdig (libs/jars) failed to start"
            if [ -s "${RAW_OUTPUT}.err" ]; then
                cat "${RAW_OUTPUT}.err"
            fi
            SYSDIG_OK=false
        else
            sleep 0.5
        fi
    else
        break
    fi
done

for i in {1..5}; do
    if ! kill -0 $SYSDIG_EXEC_PID 2>/dev/null; then
        if [ $i -eq 5 ]; then
            echo "      ✗ ERROR: sysdig (execve) failed to start"
            if [ -s "${RAW_OUTPUT}.execve.err" ]; then
                cat "${RAW_OUTPUT}.execve.err"
            fi
            SYSDIG_OK=false
        else
            sleep 0.5
        fi
    else
        break
    fi
done

if [ "$SYSDIG_OK" = "false" ]; then
    exit 1
fi

echo "      ✓ Monitoring started successfully"

# --- STEP 3: Start container ---
echo ""
echo "[3/5] Starting container to trigger resource loading..."
docker start "$CNAME"

# Wait for container to be running
timeout 60 bash -c "until docker inspect -f '{{.State.Running}}' '$CNAME' 2>/dev/null | grep -q true; do sleep 1; done" || {
    echo "      ✗ ERROR: Container failed to start within 60 seconds"
    kill $SYSDIG_PID $SYSDIG_EXEC_PID 2>/dev/null || true
    exit 1
}

echo "      ✓ Container started"

# --- STEP 4: Monitor with progress ---
echo ""
echo "[4/5] Capturing events for ${DURATION}s..."
echo -n "      Progress: "

ELAPSED=0
while [ $ELAPSED -lt $DURATION ]; do
    sleep 5
    ELAPSED=$((ELAPSED + 5))

    # Check if sysdig is still running
    if ! kill -0 $SYSDIG_PID 2>/dev/null; then
        echo ""
        echo "      ⚠ Sysdig stopped at ${ELAPSED}s"
        break
    fi

    # Show progress
    if [ $((ELAPSED % 10)) -eq 0 ]; then
        if [ -s "$RAW_OUTPUT" ]; then
            EVENTS=$(wc -l < "$RAW_OUTPUT" 2>/dev/null || echo "0")
            echo -n "${ELAPSED}s(${EVENTS}) "
        else
            echo -n "${ELAPSED}s "
        fi
    else
        echo -n "."
    fi
done

echo ""
echo "      ✓ Capture complete"

# Stop both sysdig processes gracefully
# Note: They should auto-stop due to -M flag, but kill them to be sure
kill $SYSDIG_PID 2>/dev/null || true
kill $SYSDIG_EXEC_PID 2>/dev/null || true

# Wait briefly for processes to flush and exit
sleep 2

# Force kill if still running
kill -9 $SYSDIG_PID 2>/dev/null || true
kill -9 $SYSDIG_EXEC_PID 2>/dev/null || true

# --- STEP 5: Process captured data ---
echo ""
echo "[5/5] Processing captured data..."

if [ ! -s "$RAW_OUTPUT" ] && [ ! -s "${RAW_OUTPUT}.execve" ]; then
    echo "      ✗ ERROR: No data captured!"
    echo ""
    if [ -s "${RAW_OUTPUT}.err" ]; then
        echo "Libs/JARs errors:"
        cat "${RAW_OUTPUT}.err"
    fi
    if [ -s "${RAW_OUTPUT}.execve.err" ]; then
        echo "Execve errors:"
        cat "${RAW_OUTPUT}.execve.err"
    fi
    exit 1
fi

LIBS_JAR_EVENTS=$(wc -l < "$RAW_OUTPUT" 2>/dev/null || echo "0")
EXEC_EVENTS=$(wc -l < "${RAW_OUTPUT}.execve" 2>/dev/null || echo "0")
TOTAL_EVENTS=$((LIBS_JAR_EVENTS + EXEC_EVENTS))
echo "      Total events captured: $TOTAL_EVENTS (libs/jars: $LIBS_JAR_EVENTS, execve: $EXEC_EVENTS)"

# Extract libraries (.so files from open/openat/openat2/mmap)
# Format: timestamp event_type proc.pid proc.name filename fd.typechar
# For open/mmap events, filename is column 5
echo "      Processing libraries..."
grep -a -E '\.(so|so\.[0-9]+)' "$RAW_OUTPUT" | \
  grep -a -E 'open|openat|openat2|mmap' | \
  grep -a -v '/gconv/' | \
  grep -a -v '/audit/' | \
  sort -u > "$LIBS_OUTPUT"
LIBS_COUNT=$(wc -l < "$LIBS_OUTPUT")
echo "        ✓ Found $LIBS_COUNT unique libraries"

# Create unique libs list (filename is column 5: timestamp event_type pid proc.name filename fd.typechar)
awk '{print $5}' "$LIBS_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/jni_libs_opened.txt"
UNIQUE_LIBS=$(wc -l < "$SYSDIG_OUTPUT_DIR/jni_libs_opened.txt")
echo "        ✓ $UNIQUE_LIBS unique library files"

# Create PID mapping: PID -> Process Name -> Library
awk '{print $3 "\t" $4 "\t" $5}' "$LIBS_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/libs_by_pid.txt"
echo "        ✓ PID mapping saved to libs_by_pid.txt"

# Extract binaries (files from execve events)
# Format from execve capture: timestamp event_type process_name proc.exe
echo "      Processing executables..."
if [ -s "${RAW_OUTPUT}.execve" ]; then
    # Filter corrupted lines: only keep lines with valid timestamp format at the start
    # Valid format: HH:MM:SS.nanoseconds execve process_name path
    grep -a '^[0-9][0-9]:[0-9][0-9]:[0-9][0-9]\.[0-9]' "${RAW_OUTPUT}.execve" | sort -u > "$BINARIES_OUTPUT"
    BINS_COUNT=$(wc -l < "$BINARIES_OUTPUT")
    echo "        ✓ Found $BINS_COUNT executable invocations"

    # Create unique binaries list (column 4 is proc.exe)
    # Filter out invalid paths:
    # - Paths that contain timestamps (digits followed by colon)
    # - Paths with "execve" in them (corrupted merged lines)
    awk '{print $4}' "$BINARIES_OUTPUT" | \
      grep -v '[0-9]:[0-9]' | \
      grep -v 'execve' | \
      sort -u > "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_NAME}.txt"
    UNIQUE_BINS=$(wc -l < "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_NAME}.txt")
    echo "        ✓ $UNIQUE_BINS unique executables"

    # Resolve relative paths - check both container and host
    echo "        ⚙ Resolving relative binary paths..."
    > "$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
    > "$SYSDIG_OUTPUT_DIR/binaries_host_${IMG_NAME}.txt"

    while read -r bin_path; do
        [ -z "$bin_path" ] && continue

        # Skip /proc, /sys, /dev paths
        [[ "$bin_path" =~ ^/(proc|sys|dev)/ ]] && continue

        # If relative path, try to resolve it
        if [[ ! "$bin_path" =~ ^/ ]]; then
            # First try inside container
            resolved_path=$(docker exec "$CONTAINER_ID" which "$bin_path" 2>/dev/null || \
                           docker exec "$CONTAINER_ID" sh -c "command -v $bin_path" 2>/dev/null || \
                           echo "")

            if [ -n "$resolved_path" ] && [[ "$resolved_path" =~ ^/ ]]; then
                echo "$resolved_path" >> "$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
            else
                # Try on host (for binaries like runc, docker, containerd)
                host_path=$(which "$bin_path" 2>/dev/null || echo "")
                if [ -n "$host_path" ] && [ -f "$host_path" ]; then
                    echo "$host_path" >> "$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
                    echo "$host_path" >> "$SYSDIG_OUTPUT_DIR/binaries_host_${IMG_NAME}.txt"
                else
                    echo "$bin_path" >> "$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
                fi
            fi
        else
            echo "$bin_path" >> "$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
        fi
    done < "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_NAME}.txt"
    echo "        ✓ Resolved paths saved"
else
    echo "        ⚠ No executable events captured"
    touch "$BINARIES_OUTPUT"
    touch "$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_NAME}.txt"
fi

# Extract JAR files (open/openat/openat2/mmap — JVM often mmap()s JAR/ZIP files)
echo "      Processing JAR files..."
grep -a '\.jar' "$RAW_OUTPUT" | \
  grep -a -E 'open|openat|openat2|mmap' | \
  sort -u > "$JARS_OUTPUT"
JARS_COUNT=$(wc -l < "$JARS_OUTPUT")
echo "        ✓ Found $JARS_COUNT JAR file accesses"

# Create unique JARs list (filename is column 5: timestamp event_type pid proc.name filename fd.typechar)
awk '{print $5}' "$JARS_OUTPUT" | sort -u > "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_NAME}.txt"
UNIQUE_JARS=$(wc -l < "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_NAME}.txt")
echo "        ✓ $UNIQUE_JARS unique JAR files"

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                      Capture Summary                         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  Native Libraries: $LIBS_COUNT events → $UNIQUE_LIBS unique"
echo "  Executables:      $BINS_COUNT events → $UNIQUE_BINS unique"
echo "  JAR Files:        $JARS_COUNT events → $UNIQUE_JARS unique"
echo ""
echo "  Output directory: $SYSDIG_OUTPUT_DIR/"
echo ""

# --- STEP 6: Extract resources from container ---
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                  Extracting Resources                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Create destination directories
LIBS_DIR="${PROJECT_ROOT}/LIBS_${IMG_NAME}"
BINS_DIR="${PROJECT_ROOT}/BINARIES_${IMG_NAME}"
JARS_DIR="${PROJECT_ROOT}/JARFILES_${IMG_NAME}"

mkdir -p "$LIBS_DIR" "$BINS_DIR" "$JARS_DIR"

# Extract libraries
echo "[1/3] Extracting native libraries to $LIBS_DIR/..."
LIB_SUCCESS=0
LIB_FAILED=0

while read -r lib_path; do
    [ -z "$lib_path" ] && continue

    if docker exec "$CONTAINER_ID" test -e "$lib_path" 2>/dev/null; then
        real_path=$(docker exec "$CONTAINER_ID" readlink -f "$lib_path" 2>/dev/null || echo "$lib_path")
        lib_name=$(basename "$real_path")

        if docker cp "$CONTAINER_ID:$real_path" "$LIBS_DIR/" 2>/dev/null; then
            LIB_SUCCESS=$((LIB_SUCCESS + 1))
            [ $((LIB_SUCCESS % 10)) -eq 0 ] && echo "      Copied $LIB_SUCCESS libraries..."
        else
            LIB_FAILED=$((LIB_FAILED + 1))
        fi
    else
        LIB_FAILED=$((LIB_FAILED + 1))
    fi
done < "$SYSDIG_OUTPUT_DIR/jni_libs_opened.txt"

echo "      ✓ Success: $LIB_SUCCESS libraries"
[ $LIB_FAILED -gt 0 ] && echo "      ⚠ Failed: $LIB_FAILED libraries"

# Extract binaries
echo ""
echo "[2/3] Extracting executables to $BINS_DIR/..."
BIN_SUCCESS=0
BIN_FAILED=0
BIN_HOST=0
BIN_FAILED_LIST="$SYSDIG_OUTPUT_DIR/failed_binaries.txt"
> "$BIN_FAILED_LIST"

# Use resolved paths if available, otherwise fall back to unique list
BINARIES_SOURCE="$SYSDIG_OUTPUT_DIR/binaries_resolved_${IMG_NAME}.txt"
if [ ! -s "$BINARIES_SOURCE" ]; then
    BINARIES_SOURCE="$SYSDIG_OUTPUT_DIR/binaries_unique_${IMG_NAME}.txt"
fi

# Load host binaries list
declare -A HOST_BINARIES
if [ -f "$SYSDIG_OUTPUT_DIR/binaries_host_${IMG_NAME}.txt" ]; then
    while read -r host_bin; do
        HOST_BINARIES["$host_bin"]=1
    done < "$SYSDIG_OUTPUT_DIR/binaries_host_${IMG_NAME}.txt"
fi

while read -r bin_path; do
    [ -z "$bin_path" ] && continue

    # Skip /proc, /sys, /dev paths
    [[ "$bin_path" =~ ^/(proc|sys|dev)/ ]] && continue

    # Skip if still relative (couldn't be resolved)
    if [[ ! "$bin_path" =~ ^/ ]]; then
        BIN_FAILED=$((BIN_FAILED + 1))
        echo "$bin_path (unresolved relative path)" >> "$BIN_FAILED_LIST"
        continue
    fi

    bin_name=$(basename "$bin_path")

    # Check if this is a host binary
    if [ "${HOST_BINARIES[$bin_path]}" = "1" ]; then
        # Copy from host filesystem
        if [ -f "$bin_path" ]; then
            if cp "$bin_path" "$BINS_DIR/" 2>/dev/null; then
                BIN_SUCCESS=$((BIN_SUCCESS + 1))
                BIN_HOST=$((BIN_HOST + 1))
                echo "      ✓ $bin_name (host)"
            else
                BIN_FAILED=$((BIN_FAILED + 1))
                echo "$bin_path (host cp failed)" >> "$BIN_FAILED_LIST"
            fi
        else
            BIN_FAILED=$((BIN_FAILED + 1))
            echo "$bin_path (not found on host)" >> "$BIN_FAILED_LIST"
        fi
    else
        # Copy from container
        if docker exec "$CONTAINER_ID" test -e "$bin_path" 2>/dev/null; then
            real_path=$(docker exec "$CONTAINER_ID" readlink -f "$bin_path" 2>/dev/null || echo "$bin_path")

            # Only copy if it's actually a file
            if docker exec "$CONTAINER_ID" test -f "$real_path" 2>/dev/null; then
                if docker cp "$CONTAINER_ID:$real_path" "$BINS_DIR/" 2>/dev/null; then
                    BIN_SUCCESS=$((BIN_SUCCESS + 1))
                    echo "      ✓ $bin_name"
                else
                    BIN_FAILED=$((BIN_FAILED + 1))
                    echo "$bin_path (docker cp failed)" >> "$BIN_FAILED_LIST"
                fi
            else
                BIN_FAILED=$((BIN_FAILED + 1))
                echo "$bin_path (not a file)" >> "$BIN_FAILED_LIST"
            fi
        else
            BIN_FAILED=$((BIN_FAILED + 1))
            echo "$bin_path (does not exist in container)" >> "$BIN_FAILED_LIST"
        fi
    fi
done < "$BINARIES_SOURCE"

echo "      ✓ Success: $BIN_SUCCESS executables"
if [ $BIN_HOST -gt 0 ]; then
    echo "      ✓ Host binaries: $BIN_HOST (runc, containerd, etc.)"
fi
if [ $BIN_FAILED -gt 0 ]; then
    echo "      ⚠ Failed: $BIN_FAILED executables"
    echo "        Failed binaries saved to: $BIN_FAILED_LIST"
    echo "        First 5 failures:"
    head -5 "$BIN_FAILED_LIST" | sed 's/^/          /'
fi

# Extract JARs
echo ""
echo "[3/3] Extracting JAR files to $JARS_DIR/..."
JAR_SUCCESS=0
JAR_FAILED=0

while read -r jar_path; do
    [ -z "$jar_path" ] && continue

    jar_name=$(basename "$jar_path")

    if docker cp "$CONTAINER_ID:$jar_path" "$JARS_DIR/$jar_name" 2>/dev/null; then
        JAR_SUCCESS=$((JAR_SUCCESS + 1))
        [ $((JAR_SUCCESS % 10)) -eq 0 ] && echo "      Copied $JAR_SUCCESS JARs..."
    else
        JAR_FAILED=$((JAR_FAILED + 1))
    fi
done < "$SYSDIG_OUTPUT_DIR/jars_unique_${IMG_NAME}.txt"

echo "      ✓ Success: $JAR_SUCCESS JARs"
[ $JAR_FAILED -gt 0 ] && echo "      ⚠ Failed: $JAR_FAILED JARs"

# Extract NSS libraries (Name Service Switch - dynamically loaded by libc)
echo ""
echo "[4/4] Extracting NSS libraries to $LIBS_DIR/..."
echo "      NSS libraries are dynamically loaded by libc via dlopen()"
echo "      and are needed for hostname resolution, user lookups, etc."
NSS_SUCCESS=0
NSS_FAILED=0

# Common locations to search for NSS libraries
NSS_PATHS=(
    "/lib/x86_64-linux-gnu"
    "/usr/lib/x86_64-linux-gnu"
    "/lib64"
    "/usr/lib64"
    "/lib/aarch64-linux-gnu"
    "/usr/lib/aarch64-linux-gnu"
)

# Dynamically discover NSS libraries in container
for nss_path in "${NSS_PATHS[@]}"; do
    # Check if directory exists in container
    if docker exec "$CONTAINER_ID" test -d "$nss_path" 2>/dev/null; then
        # Find all libnss* and libresolv* libraries
        nss_libs=$(docker exec "$CONTAINER_ID" sh -c "ls $nss_path 2>/dev/null | grep -E '^lib(nss_|resolv)'" 2>/dev/null || true)

        if [ -n "$nss_libs" ]; then
            echo "      Scanning $nss_path..."

            while IFS= read -r nss_lib; do
                [ -z "$nss_lib" ] && continue

                full_path="$nss_path/$nss_lib"

                # Resolve symlinks
                real_path=$(docker exec "$CONTAINER_ID" readlink -f "$full_path" 2>/dev/null || echo "$full_path")

                # Only copy if it's a regular file (not already copied)
                if [ ! -f "$LIBS_DIR/$(basename "$real_path")" ]; then
                    if docker cp "$CONTAINER_ID:$real_path" "$LIBS_DIR/" 2>/dev/null; then
                        NSS_SUCCESS=$((NSS_SUCCESS + 1))
                        echo "        ✓ $(basename "$real_path")"

                        # If original was a symlink, create the symlink locally too
                        if [ "$real_path" != "$full_path" ]; then
                            target_name=$(basename "$real_path")
                            if [ "$target_name" != "$nss_lib" ] && [ ! -f "$LIBS_DIR/$nss_lib" ]; then
                                ln -sf "$target_name" "$LIBS_DIR/$nss_lib" 2>/dev/null || \
                                cp "$LIBS_DIR/$target_name" "$LIBS_DIR/$nss_lib" 2>/dev/null || true
                            fi
                        fi
                    else
                        NSS_FAILED=$((NSS_FAILED + 1))
                    fi
                fi
            done <<< "$nss_libs"
        fi
    fi
done

if [ $NSS_SUCCESS -gt 0 ]; then
    echo "      ✓ Success: $NSS_SUCCESS NSS libraries"
else
    echo "      ⚠ No NSS libraries found in container"
fi
[ $NSS_FAILED -gt 0 ] && echo "      ⚠ Failed: $NSS_FAILED NSS libraries"

# Final summary
echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                     Extraction Complete                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Sysdig Outputs:     $SYSDIG_OUTPUT_DIR/"
echo "Native Libraries:   $LIBS_DIR/ ($LIB_SUCCESS files)"
echo "NSS Libraries:      $LIBS_DIR/ (+$NSS_SUCCESS NSS files)"
echo "Executables:        $BINS_DIR/ ($BIN_SUCCESS files)"
echo "JAR Files:          $JARS_DIR/ ($JAR_SUCCESS files)"
echo ""
echo "Next step:"
echo "  Run: ./scripts/automate_syscall_analysis.sh --img-name $IMG_NAME --log"
echo ""