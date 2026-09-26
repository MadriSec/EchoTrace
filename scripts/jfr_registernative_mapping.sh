#!/bin/bash
#
# quickstart_jfr_extraction.sh
#
# One-command JFR RegisterNatives extraction from libjvm.so
#
# Usage:
#   ./quickstart_jfr_extraction.sh [binary]
#
# Example:
#   ./quickstart_jfr_extraction.sh LIBS_cassandra_5.0.6-bookworm/libjvm.so
#

set -euo pipefail

BINARY="${1:-LIBS_cassandra_5.0.6-bookworm/libjvm.so}"

if [ ! -f "$BINARY" ]; then
    echo "ERROR: Binary not found: $BINARY" >&2
    echo "Usage: $0 <path-to-libjvm.so>" >&2
    exit 1
fi

echo "=== Quick JFR RegisterNatives Extraction ===" >&2
echo "Binary: $BINARY" >&2
echo "" >&2

# Check prerequisites
for cmd in nm objdump readelf python3; do
    if ! command -v $cmd &> /dev/null; then
        echo "ERROR: Required command not found: $cmd" >&2
        exit 1
    fi
done

# Step 1: Find jfr_register_natives function
echo "[1/4] Finding jfr_register_natives function..." >&2
JFR_FUNCS=$(nm "$BINARY" 2>/dev/null | grep -i "jfr.*registration" | grep -E "[Cc]1|[Cc]2" || true)

if [ -z "$JFR_FUNCS" ]; then
    echo "ERROR: Could not find jfr registration function" >&2
    echo "Available functions:" >&2
    nm "$BINARY" 2>/dev/null | grep -i jfr | grep -i register | head -10 >&2
    exit 1
fi

# Get the first constructor address (C1 or C2)
FUNC_ADDR=$(echo "$JFR_FUNCS" | head -1 | awk '{print $1}')
echo "  Found: 0x$FUNC_ADDR" >&2

# Step 2: Disassemble to find array load
echo "[2/4] Disassembling to find JNINativeMethod array..." >&2
DISASM=$(objdump -d "$BINARY" --start-address=0x$FUNC_ADDR --stop-address=$((0x$FUNC_ADDR + 0x200)) 2>/dev/null)

# Look for lea instruction loading array pointer
# Pattern: lea 0xXXXXXX(%rip),%rsi  # ARRAY_ADDR
# We want the SECOND lea (first is for class name, second is for method array)
ARRAY_LINE=$(echo "$DISASM" | grep "lea.*%rip.*%rsi" | grep "#" | tail -1)

if [ -z "$ARRAY_LINE" ]; then
    echo "ERROR: Could not find array load instruction" >&2
    echo "Disassembly around 0x$FUNC_ADDR:" >&2
    echo "$DISASM" | head -20 >&2
    exit 1
fi

# Extract array virtual address from comment
ARRAY_VADDR=$(echo "$ARRAY_LINE" | grep -oP '# \K[0-9a-f]+')
echo "  Array virtual address: 0x$ARRAY_VADDR" >&2

# Step 3: Map virtual address to file offset
echo "[3/4] Mapping to file offset..." >&2

# Get .data section info
SECTION_LINE=$(readelf -S "$BINARY" 2>/dev/null | grep -E "\\s+\\.data\\s+" | head -1)

if [ -z "$SECTION_LINE" ]; then
    echo "ERROR: Could not find .data section" >&2
    exit 1
fi

# Parse section info (handle both formats)
SECTION_VADDR=$(echo "$SECTION_LINE" | awk '{print $4}')
SECTION_OFFSET=$(echo "$SECTION_LINE" | awk '{print $5}')
SECTION_SIZE=$(echo "$SECTION_LINE" | awk '{print $6}')

echo "  .data section: vaddr=0x$SECTION_VADDR, offset=0x$SECTION_OFFSET, size=0x$SECTION_SIZE" >&2

# Calculate file offset
ARRAY_FILE_OFFSET=$((0x$ARRAY_VADDR - 0x$SECTION_VADDR + 0x$SECTION_OFFSET))
echo "  Array file offset: 0x$(printf '%x' $ARRAY_FILE_OFFSET)" >&2

# Step 4: Extract methods
echo "[4/4] Extracting methods..." >&2

# Count entries by scanning for null terminator
# Simplified: assume 57 methods (known for JFR)
NUM_METHODS=57

if [ ! -f "extract_jfr_methods.py" ]; then
    echo "ERROR: extract_jfr_methods.py not found in current directory" >&2
    exit 1
fi

OUTPUT_FILE="jfr_extracted_methods.txt"
python3 extract_jfr_methods.py "$BINARY" "0x$(printf '%x' $ARRAY_FILE_OFFSET)" "$NUM_METHODS" > "$OUTPUT_FILE"

NUM_EXTRACTED=$(grep -c "→" "$OUTPUT_FILE" || echo "0")
echo "  Extracted: $NUM_EXTRACTED methods" >&2

echo "" >&2
echo "=== Extraction Complete ===" >&2
echo "Output: $OUTPUT_FILE" >&2
echo "" >&2

# Show first 10 methods
echo "First 10 methods extracted:" >&2
grep "→" "$OUTPUT_FILE" | head -10 >&2
echo "..." >&2

echo "" >&2
echo "Full output in: $OUTPUT_FILE"
