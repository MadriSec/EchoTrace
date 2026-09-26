#!/bin/bash
# Build script for JNA test fixtures
# Creates two separate JARs to verify caller/callee JAR tracking

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build"
OUT_DIR="$SCRIPT_DIR/jars"

# Find JNA jar for compilation
JNA_JAR=$(find /home/rupesh.punna/Prototype -name "jna-5*.jar" ! -name "*platform*" | head -1)
if [ -z "$JNA_JAR" ]; then
    echo "ERROR: Could not find JNA jar"
    exit 1
fi
echo "Using JNA jar: $JNA_JAR"

# Clean and create directories
rm -rf "$BUILD_DIR" "$OUT_DIR"
mkdir -p "$BUILD_DIR/mylib" "$BUILD_DIR/myapp" "$OUT_DIR"

echo "=== Building mylib.jar (contains CLib, PosixLib, MyKernel32 interfaces) ==="
# Compile all library interfaces
javac -cp "$JNA_JAR" \
    -d "$BUILD_DIR/mylib" \
    "$SCRIPT_DIR/CLib.java" \
    "$SCRIPT_DIR/PosixLib.java" \
    "$SCRIPT_DIR/MyKernel32.java"

# Create mylib.jar
jar cf "$OUT_DIR/mylib.jar" -C "$BUILD_DIR/mylib" .
echo "Created: $OUT_DIR/mylib.jar"
jar tf "$OUT_DIR/mylib.jar"

echo ""
echo "=== Building myapp.jar (contains MyApp, WinApp, EdgeCases) ==="
# Compile all application classes with mylib.jar on classpath
javac -cp "$JNA_JAR:$OUT_DIR/mylib.jar" \
    -d "$BUILD_DIR/myapp" \
    "$SCRIPT_DIR/MyApp.java" \
    "$SCRIPT_DIR/WinApp.java" \
    "$SCRIPT_DIR/EdgeCases.java"

# Create myapp.jar
jar cf "$OUT_DIR/myapp.jar" -C "$BUILD_DIR/myapp" .
echo "Created: $OUT_DIR/myapp.jar"
jar tf "$OUT_DIR/myapp.jar"

echo ""
echo "=== Copying JNA jar for analysis ==="
cp "$JNA_JAR" "$OUT_DIR/"
echo "Copied: $JNA_JAR"

echo ""
echo "=== Test JARs ready in: $OUT_DIR ==="
ls -la "$OUT_DIR"

echo ""
echo "=== Expected Detection ==="
cat << 'EOF'
When running JnaIfaceDetector on $OUT_DIR, we should see:

Format: callerSig | lib | symbol | interface | calleeSig | callerJar | calleeJar

--- MyApp (basic INSTANCE pattern) ---
1. <com.example.app.MyApp: int getStringLength(java.lang.String)> | c | strlen | com.example.native_lib.CLib | <com.example.native_lib.CLib: int strlen(java.lang.String)> | myapp.jar | mylib.jar
2. <com.example.app.MyApp: int getCurrentProcessId()> | c | getpid | com.example.native_lib.CLib | <com.example.native_lib.CLib: int getpid()> | myapp.jar | mylib.jar
3. <com.example.app.MyApp: int getCurrentUserId()> | c | getuid | com.example.native_lib.CLib | <com.example.native_lib.CLib: int getuid()> | myapp.jar | mylib.jar

--- WinApp (StdCallLibrary inheritance) ---
4. <com.example.app.WinApp: void makeBeep()> | kernel32 | Beep | com.example.native_lib.MyKernel32 | ... | myapp.jar | mylib.jar
5. <com.example.app.WinApp: int getPid()> | kernel32 | GetCurrentProcessId | ... | myapp.jar | mylib.jar
6. <com.example.app.WinApp: void setTitle(java.lang.String)> | kernel32 | SetConsoleTitle | ... | myapp.jar | mylib.jar

--- EdgeCases (edge case patterns) ---
7. EdgeCases.getpidViaInstance2 | c | getpid | CLib        (different field name: INSTANCE2)
8. EdgeCases.strlenViaInstance2 | c | strlen | CLib        (different field name: INSTANCE2)
9. EdgeCases.getpidViaPosixLib  | <null:default-c-lib> | getpid | PosixLib  (different interface + null lib)
10. EdgeCases.localVarUsage     | c | strlen | CLib        (local variable, not field)

Key verification:
- callerJar = myapp.jar (where app classes are defined)
- calleeJar = mylib.jar (where JNA interfaces are defined)
EOF
