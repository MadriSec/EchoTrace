#!/usr/bin/env python3
"""
extract_jfr_methods.py

Extracts JFR (Java Flight Recorder) RegisterNatives methods from libjvm.so
by parsing the JNINativeMethod array in the .data section.

Usage:
    python3 extract_jfr_methods.py [binary] [array_offset] [num_methods]

Example:
    python3 extract_jfr_methods.py LIBS_cassandra_5.0.6-bookworm/libjvm.so 0x12c6f40 57
"""

import struct
import subprocess
import sys

# Default values (can be overridden via command line)
BINARY = "LIBS_cassandra_5.0.6-bookworm/libjvm.so"
ARRAY_FILE_OFFSET = 0x12c6f40
NUM_METHODS = 57
ENTRY_SIZE = 24  # JNINativeMethod = 3 pointers × 8 bytes

def get_sections(binary_path):
    """Extract section information from binary using readelf"""
    result = subprocess.run(['readelf', '-S', binary_path],
                          capture_output=True, text=True, check=True)
    sections = {}

    lines = result.stdout.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        if '.data' in line or '.rodata' in line or '.text' in line:
            parts = line.split()
            if len(parts) >= 5:
                # Handle both formats: with and without leading bracket
                name = parts[1] if parts[0].startswith('[') else parts[0]
                try:
                    idx = 3 if parts[0].startswith('[') else 2
                    vaddr = int(parts[idx], 16)
                    offset = int(parts[idx+1], 16)

                    # Size might be on same line or next line
                    if len(parts) > idx+2:
                        size = int(parts[idx+2], 16)
                    else:
                        # Size is on next line
                        i += 1
                        if i < len(lines):
                            next_parts = lines[i].split()
                            if next_parts and next_parts[0].startswith('0'):
                                size = int(next_parts[0], 16)
                            else:
                                continue
                        else:
                            continue

                    sections[name] = {
                        'vaddr': vaddr,
                        'offset': offset,
                        'size': size
                    }
                except (ValueError, IndexError):
                    pass
        i += 1

    return sections

def vaddr_to_file_offset(vaddr, sections):
    """Convert virtual address to file offset using section mappings"""
    for name, sec in sections.items():
        if sec['vaddr'] <= vaddr < sec['vaddr'] + sec['size']:
            return sec['offset'] + (vaddr - sec['vaddr'])
    return None

def read_string(binary_path, offset, max_len=256):
    """Read null-terminated string from binary at given file offset"""
    if offset is None:
        return None

    try:
        with open(binary_path, 'rb') as f:
            f.seek(offset)
            data = f.read(max_len)

            null_pos = data.find(b'\x00')
            if null_pos == -1:
                return None

            return data[:null_pos].decode('utf-8')
    except Exception:
        return None

def get_symbol_for_addr(binary_path, addr):
    """Find symbol name for given address using nm"""
    try:
        result = subprocess.run(['nm', binary_path],
                              capture_output=True, text=True, check=True)

        best_match = None
        best_distance = float('inf')

        for line in result.stdout.split('\n'):
            parts = line.split()
            if len(parts) >= 3 and parts[1] in 'tTwW':
                try:
                    sym_addr = int(parts[0], 16)
                    sym_name = parts[2]
                    distance = abs(addr - sym_addr)

                    if distance < best_distance and distance < 0x100:
                        best_distance = distance
                        best_match = sym_name
                except ValueError:
                    pass

        if best_match:
            if best_distance == 0:
                return best_match
            else:
                return f"{best_match}+0x{best_distance:x}"

    except Exception:
        pass

    return f"<0x{addr:x}>"

def extract_methods(binary_path, array_offset, num_methods):
    """Extract RegisterNatives methods from JNINativeMethod array"""

    # Get section mappings
    sections = get_sections(binary_path)

    print(f"# JFR RegisterNatives Methods Extracted from {binary_path}", file=sys.stderr)
    print(f"# Array at file offset: 0x{array_offset:x}", file=sys.stderr)
    print(f"# Total methods: {num_methods}", file=sys.stderr)
    print(f"", file=sys.stderr)

    print(f"# Format: jdk.jfr.internal.JVM.method_name(signature) → native_symbol")
    print("")

    extracted = []

    with open(binary_path, 'rb') as f:
        f.seek(array_offset)

        for i in range(num_methods):
            entry_data = f.read(ENTRY_SIZE)
            if len(entry_data) < ENTRY_SIZE:
                print(f"# WARNING: Only read {len(entry_data)} bytes for entry {i+1}",
                      file=sys.stderr)
                break

            # Parse JNINativeMethod struct (3 × 64-bit pointers)
            name_ptr, sig_ptr, fn_ptr = struct.unpack('<QQQ', entry_data)

            # Skip null entries
            if name_ptr == 0 or sig_ptr == 0 or fn_ptr == 0:
                continue

            # Resolve pointers to strings
            name_offset = vaddr_to_file_offset(name_ptr, sections)
            sig_offset = vaddr_to_file_offset(sig_ptr, sections)

            method_name = read_string(binary_path, name_offset) if name_offset else "<?>"
            signature = read_string(binary_path, sig_offset) if sig_offset else "<?>"
            symbol = get_symbol_for_addr(binary_path, fn_ptr)

            # Format output
            entry = f"{i+1:2d}. jdk.jfr.internal.JVM.{method_name}{signature} → {symbol}"
            print(entry)
            extracted.append((method_name, signature, symbol))

    return extracted

def main():
    if len(sys.argv) > 1:
        binary = sys.argv[1]
    else:
        binary = BINARY

    if len(sys.argv) > 2:
        array_offset = int(sys.argv[2], 16 if sys.argv[2].startswith('0x') else 10)
    else:
        array_offset = ARRAY_FILE_OFFSET

    if len(sys.argv) > 3:
        num_methods = int(sys.argv[3])
    else:
        num_methods = NUM_METHODS

    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print(__doc__)
        sys.exit(0)

    extracted = extract_methods(binary, array_offset, num_methods)

    print("", file=sys.stderr)
    print(f"# Extraction complete: {len(extracted)} methods", file=sys.stderr)

if __name__ == '__main__':
    main()
