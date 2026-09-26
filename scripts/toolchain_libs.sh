#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

CONTAINER_ID=$1
if [ -z "$CONTAINER_ID" ]; then
  echo "ERROR: Container ID not provided!"
  exit 1
fi

CNAME=$(docker inspect -f '{{.Name}}' "$CONTAINER_ID" | sed 's/^\///')
CONTPID=$(docker inspect -f '{{.State.Pid}}' "$CONTAINER_ID")
CG=$(awk -F: '/:\/docker\//{print $3} $0~/0::/{print $3}' /proc/$CONTPID/cgroup | head -1)

# Derive image-safe suffix for output directories
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CNAME")
IMG_NAME=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')

# Create outputs directory for this container
OUTPUTS_DIR="${PROJECT_ROOT}/outputs_${IMG_NAME}"
mkdir -p "$OUTPUTS_DIR"

echo "Container Name: $CNAME"
echo "Container PID: $CONTPID"
echo "Container cgroup: $CG"
echo "Output directory: $OUTPUTS_DIR"
echo "------------------------------------------------------------"

# --- STEP 2: Stop container first to ensure clean restart ---
echo "Stopping container '$CNAME' to ensure clean restart..."
docker stop "$CNAME" 2>/dev/null || true
sleep 2

# --- STEP 3: Capture libraries with sysdig ---
echo "Starting sysdig to monitor library loads (will run for 90 seconds)..."
echo "Debug: Container Name: $CNAME"
echo "Debug: Container ID: $CONTAINER_ID"
echo "Debug: Container cgroup: $CG"
RAW_LIBS="${OUTPUTS_DIR}/libs_loaded_raw.txt"

# Use container.name only (most reliable across restarts)
# Note: We use container.name instead of cgroup because the container is stopped/restarted,
# causing the PID and cgroup to change, but the name remains stable
echo "Using container.name filter (stable across restarts)"
sudo sysdig --modern-bpf -M 120 \
  "container.name=$CNAME and evt.type in (open,openat,openat2,mmap) and fd.name contains .so" \
  -p "%evt.time %proc.name %fd.name" \
  > "$RAW_LIBS" 2>"${RAW_LIBS}.err" &

SYSDIG_PID=$!

# Wait for sysdig to initialize and attach BPF probes
echo "Waiting for sysdig to initialize (10 seconds)..."
sleep 10

# Verify sysdig is still running
if ! kill -0 $SYSDIG_PID 2>/dev/null; then
  echo "ERROR: sysdig failed to start properly"
  if [ -s "${RAW_LIBS}.err" ]; then
    echo "Sysdig error output:"
    cat "${RAW_LIBS}.err"
  fi
  exit 1
fi

echo "Starting container '$CNAME' to trigger the loading of all files..."
docker start "$CNAME"

# Wait for container to be running
echo "Waiting for container to fully start..."
timeout 60 bash -c "until docker inspect -f '{{.State.Running}}' '$CNAME' 2>/dev/null | grep -q true; do sleep 1; done" || {
  echo "ERROR: Container failed to start within 60 seconds"
  kill $SYSDIG_PID 2>/dev/null || true
  exit 1
}

# Give the application time to fully initialize and load libraries
echo "Waiting for application initialization and library loading (will capture for 120s)..."
timeout 125s bash -c "wait $SYSDIG_PID" || { kill $SYSDIG_PID 2>/dev/null || true; }

# Wait for output buffers to flush to disk
echo "Waiting for sysdig output to flush..."
sleep 3

# Post-process unique outputs after capture completes
JNI_LIBS="${OUTPUTS_DIR}/jni_libs_opened.txt"
if [ -s "$RAW_LIBS" ]; then
  sort -u "$RAW_LIBS" > "$JNI_LIBS"
else
  : > "$JNI_LIBS"
fi

echo "------------------------------------------------------------"
echo "List of loaded native libraries (.so files):"
if [ -s "$JNI_LIBS" ]; then
  cat "$JNI_LIBS"
else
  echo "No libraries captured. Trying alternative approaches..."

  # Check if sysdig captured anything
  if [ -s "${RAW_LIBS}.err" ]; then
    echo "Sysdig error output:"
    cat "${RAW_LIBS}.err"
  fi

  echo "Debug: Checking if container is running..."
  docker ps | grep "$CONTAINER_ID" || echo "Container not found in running containers"

  LIBS_ALT="${OUTPUTS_DIR}/libs_loaded_alt.txt"
  echo "Debug: Trying broader file monitoring with container.name..."
  (timeout 30s sudo sysdig --modern-bpf \
    "container.name=$CNAME and evt.type in (open,openat,openat2,mmap) and fd.name contains .so" \
    -p "%evt.time %proc.name %fd.name" \
    | sort -u > "$LIBS_ALT" 2>/dev/null) &
  ALT_PID=$!
  sleep 5
  docker restart "$CNAME" 2>/dev/null || docker start "$CNAME" 2>/dev/null || true
  timeout 35s bash -c "wait $ALT_PID" || { kill $ALT_PID 2>/dev/null || true; }

  if [ -s "$LIBS_ALT" ]; then
    echo "Found libraries with alternative approach:"
    cat "$LIBS_ALT"
    cp "$LIBS_ALT" "$JNI_LIBS"
  else
    echo "Still no libraries found. Searching container filesystem..."
    LIBS_MANUAL="${OUTPUTS_DIR}/libs_manual.txt"
    # Search for .so files but exclude gconv modules (character encoding converters) and audit modules
    docker exec "$CONTAINER_ID" find /usr/lib /lib /lib64 -name "*.so*" -type f 2>/dev/null | \
      grep -v "/gconv/" | \
      grep -v "/audit/" | \
      head -50 > "$LIBS_MANUAL"

    if [ -s "$LIBS_MANUAL" ]; then
      echo "Found libraries manually (first 20):"
      head -20 "$LIBS_MANUAL"
      # Convert to sysdig format for consistency
      awk '{print "manual " $0}' "$LIBS_MANUAL" > "$JNI_LIBS"
    else
      echo "No .so files found in standard library directories."
      echo "WARNING: No libraries captured. The script will continue but may not extract libraries."
    fi
  fi
fi
echo "------------------------------------------------------------"

# --- STEP 4: Copy libraries to host ---
DEST_DIR="${PROJECT_ROOT}/LIBS_${IMG_NAME}"
echo "Creating destination directory: $DEST_DIR"
mkdir -p "$DEST_DIR"

echo "Extracting unique native library paths..."
# Filter out "manual" prefix if present and get the last field (library path)
# Also exclude gconv modules (character encoding converters) and audit modules as they're not application libraries
LIB_FILES=$(awk '{if ($1 == "manual") print substr($0, 8); else print $NF}' "$JNI_LIBS" | \
  grep -v "^$" | \
  grep -v "/gconv/" | \
  grep -v "/audit/" | \
  sort -u)

echo "Downloading native libraries from container $CONTAINER_ID..."
LIB_COUNT=0
SUCCESS_COUNT=0
FAILED_COUNT=0

for lib_path in $LIB_FILES; do
    # Skip empty lines
    [ -z "$lib_path" ] && continue
    
    LIB_COUNT=$((LIB_COUNT + 1))
    echo "Checking $lib_path..."
    
    if docker exec "$CONTAINER_ID" test -e "$lib_path" 2>/dev/null; then
        real_path=$(docker exec "$CONTAINER_ID" readlink -f "$lib_path" 2>/dev/null || echo "$lib_path")
        lib_name=$(basename "$real_path")
        
        echo "Copying binary: $real_path..."
        if docker cp "$CONTAINER_ID:$real_path" "$DEST_DIR/" 2>/dev/null; then
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
            echo "  ✓ Successfully copied: $lib_name"
            
            # Handle symlinks
            if [ "$real_path" != "$lib_path" ]; then
                symlink_name=$(basename "$lib_path")
                target_name=$(basename "$real_path")
                if [ "$symlink_name" != "$target_name" ] && [ ! -e "$DEST_DIR/$symlink_name" ]; then
                    echo "  Creating symlink alias: $symlink_name -> $target_name"
                    cp --remove-destination "$DEST_DIR/$target_name" "$DEST_DIR/$symlink_name" 2>/dev/null || true
                fi
            fi
        else
            FAILED_COUNT=$((FAILED_COUNT + 1))
            echo "  ✗ Failed to copy: $lib_path"
        fi
    else
        FAILED_COUNT=$((FAILED_COUNT + 1))
        echo "  ✗ Skipping missing: $lib_path"
    fi
done

echo ""
echo "Library extraction summary:"
echo "  Total libraries found: $LIB_COUNT"
echo "  Successfully copied: $SUCCESS_COUNT"
echo "  Failed/missing: $FAILED_COUNT"

echo "------------------------------------------------------------"
echo "All valid native libraries have been downloaded to $DEST_DIR (no symlinks, only real binaries)."
echo ""
echo "=========================================="
echo "OUTPUT FILES SAVED"
echo "=========================================="
echo "  Output directory: $OUTPUTS_DIR"
echo "    - libs_loaded_raw.txt       - Raw sysdig library events"
echo "    - jni_libs_opened.txt       - Unique library paths"
echo "    - libs_loaded_alt.txt       - Alternative capture (if used)"
echo "    - libs_manual.txt           - Manual search results (if used)"
echo ""
echo "  Libraries extracted to: $DEST_DIR"
echo "=========================================="