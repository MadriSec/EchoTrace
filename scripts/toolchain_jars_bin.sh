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

# Derive a stable image name suffix for output dirs
IMG_RAW=$(docker inspect -f '{{.Config.Image}}' "$CONTAINER_ID" 2>/dev/null || echo "$CNAME")
IMG_NAME=$(echo "$IMG_RAW" | tr '/:@' '___' | sed 's/[^A-Za-z0-9._-]/_/g')

echo "Container Name: $CNAME"
echo "Container PID: $CONTPID"
echo "Container cgroup: $CG"
echo "------------------------------------------------------------"

# --- STEP 2: Run sysdig to capture JAR/JMOD/module loads (60s) ---
echo "Monitoring file open events for the Java application (60s)..."
echo "Debug: Using cgroup filter: $CG"
RAW_JARS="jars_loaded_raw.txt"
JARS_OUT="jars_loaded.txt"
sudo sysdig --modern-bpf -M 60 \
  "thread.cgroups contains \"$CG\" and evt.type in (open,openat,openat2) and (fd.name contains .jar or fd.name contains .jmod or fd.name contains /lib/modules or fd.name contains .class)" \
  -p "%evt.time %proc.name %fd.name" \
  > "$RAW_JARS" 2>"${RAW_JARS}.err" &
SYSDIG_JARS_PID=$!

# --- STEP 3: Run sysdig to capture executed binaries (60s) ---
echo "Monitoring executed binaries for 60s..."
RAW_BIN="binaries_abs_raw.txt"
BIN_OUT="binaries_abs.txt"
sudo sysdig --modern-bpf -M 60 \
  "evt.type=execve and thread.cgroups contains \"$CG\"" \
  -p "%evt.arg.filename" \
  > "$RAW_BIN" 2>"${RAW_BIN}.err" &
SYSDIG_BIN_PID=$!

# --- STEP 4: Give sysdig a head start ---
sleep 2

# --- STEP 5: Restart container to trigger loading ---
echo "Restarting container '$CNAME' to capture events..."
docker restart "$CNAME"

# --- STEP 6: Wait for sysdig sessions ---
timeout 75s bash -c "wait $SYSDIG_JARS_PID" || { kill $SYSDIG_JARS_PID 2>/dev/null || true; }
timeout 75s bash -c "wait $SYSDIG_BIN_PID" || { kill $SYSDIG_BIN_PID 2>/dev/null || true; }

# Post-process unique outputs after capture completes
if [ -s "$RAW_JARS" ]; then
  sort -u "$RAW_JARS" > "$JARS_OUT"
else
  : > "$JARS_OUT"
fi
if [ -s "$RAW_BIN" ]; then
  sort -u "$RAW_BIN" > "$BIN_OUT"
else
  : > "$BIN_OUT"
fi

echo "------------------------------------------------------------"
echo "JAR monitoring completed. Checking results..."

# Check if jars_loaded.txt has content
if [ -s jars_loaded.txt ]; then
    echo "Found JAR/JMOD/module files:"
    cat jars_loaded.txt
else
    echo "No JAR files found. Trying alternative approach..."
    echo "Debug: Checking if container is running..."
    docker ps | grep "$CONTAINER_ID"
    
    echo "Debug: Trying broader file monitoring..."
    (timeout 30s sudo sysdig --modern-bpf \
      "thread.cgroups contains \"$CG\" and evt.type in (open,openat,openat2)" \
      -p "%evt.time %proc.name %fd.name" \
      | grep -E "\.jar|\.jmod|\.class" | sort -u > jars_loaded_alt.txt) &
    wait $!
    
    if [ -s jars_loaded_alt.txt ]; then
        echo "Found files with alternative approach:"
        cat jars_loaded_alt.txt
        cp jars_loaded_alt.txt jars_loaded.txt
    else
       
        echo "Searching for JAR files in container filesystem..."
        docker exec "$CONTAINER_ID" find / -name "*.jar" -type f 2>/dev/null | head -20 > jars_manual.txt
        docker exec "$CONTAINER_ID" find / -name "*.jmod" -type f 2>/dev/null | head -20 >> jars_manual.txt
        
        if [ -s jars_manual.txt ]; then
            echo "Found JAR files manually:"
            cat jars_manual.txt
            cp jars_manual.txt jars_loaded.txt
        else
            echo "No JAR files found in container. Container might not have JAR files or they're in non-standard locations."
        fi
    fi
fi
echo "------------------------------------------------------------"

echo "List of executed binaries:"
cat binaries_abs.txt
echo "------------------------------------------------------------"

# --- STEP 7: Copy JAR/JMOD/module files ---
DEST_DIR_JARS="${PROJECT_ROOT}/JARFILES_${IMG_NAME}"
echo "Creating destination directory: $DEST_DIR_JARS"
mkdir -p "$DEST_DIR_JARS"

echo "Extracting unique JAR/JMOD/module file paths from sysdig output..."
JAR_FILES=$(grep -E ".jar$|.jmod$|/lib/modules" jars_loaded.txt | awk '{print $NF}' | sort -u)

echo "Downloading JAR/JMOD/module files from container $CONTAINER_ID..."
for jar_path in $JAR_FILES; do
    echo "Copying $jar_path..."
    docker cp "$CONTAINER_ID:$jar_path" "$DEST_DIR_JARS" 2>/dev/null || echo "Skipping missing: $jar_path"
done

# --- STEP 8: Copy executed binaries ---
DEST_DIR_BIN="${PROJECT_ROOT}/BINARIES_${IMG_NAME}"
echo "Creating destination directory: $DEST_DIR_BIN"
mkdir -p "$DEST_DIR_BIN"

echo "Extracting unique binary file paths from sysdig output..."
BIN_FILES=$(awk '{print $NF}' binaries_abs.txt | sort -u)

echo "Downloading binaries from container $CONTAINER_ID..."
for bin_path in $BIN_FILES; do
    echo "Copying $bin_path..."
    docker cp "$CONTAINER_ID:$bin_path" "$DEST_DIR_BIN" 2>/dev/null || echo "Skipping missing: $bin_path"
done

echo "------------------------------------------------------------"
echo "All available JAR/JMOD/module files have been downloaded to $DEST_DIR_JARS."
echo "All executed binaries have been downloaded to $DEST_DIR_BIN."
echo "------------------------------------------------------------"
