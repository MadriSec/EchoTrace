#!/usr/bin/env python3
"""
extract_registernatives_binary.py - Extract JNINativeMethod[] registration
tables directly from compiled .so binaries (no source code needed).

Approach:
  1. Find all *_registerNatives exported symbols via nm -D
  2. Disassemble each with objdump to find:
     - LEA into %rdx  -> address of JNINativeMethod[] array
     - MOV into %ecx  -> nMethods count
  3. Read nMethods * 24 bytes from the array in the binary
  4. Each 24-byte struct: [name_ptr, sig_ptr, fn_ptr]
  5. Resolve string pointers from .rodata

Usage:
    python3 scripts/extract_registernatives_binary.py <path_to.so> [...]
    python3 scripts/extract_registernatives_binary.py /path/to/libjava.so /path/to/libjvm.so
"""

from __future__ import annotations

import os
import re
import struct
import subprocess
import sys
from pathlib import Path


def run_cmd(cmd: list[str], timeout: int = 30) -> str:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return proc.stdout


def find_register_natives_symbols(so_path: str) -> list[tuple[str, int]]:
    """Return list of (symbol_name, address) for *registerNatives* exports."""
    out = run_cmd(["nm", "-D", so_path])
    results = []
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[1] == "T" and "registerNatives" in parts[2]:
            sym = parts[2].split("@@")[0]  # strip version tag
            addr = int(parts[0], 16)
            results.append((sym, addr))
    return results


def disassemble_function(so_path: str, start_addr: int, length: int = 0x60) -> str:
    """Disassemble a short range starting at start_addr."""
    end = start_addr + length
    out = run_cmd([
        "objdump", "-d", "--no-show-raw-insn",
        f"--start-address=0x{start_addr:x}",
        f"--stop-address=0x{end:x}",
        so_path
    ])
    return out


def parse_register_natives_call(disasm: str, func_addr: int) -> tuple[int, int] | None:
    """Parse disassembly to find (array_addr, n_methods).

    Looks for:
        mov    $0xNN,%ecx           -> nMethods
        lea    0xOFFSET(%rip),%rdx  -> array address
    """
    array_addr = None
    n_methods = None

    for line in disasm.splitlines():
        line = line.strip()

        # Match: mov $0x16,%ecx  (nMethods)
        m = re.search(r'mov\s+\$0x([0-9a-f]+),%ecx', line)
        if m:
            n_methods = int(m.group(1), 16)

        # Match: lea 0x1ebbd(%rip),%rdx  # 2d5a0
        # objdump usually shows the resolved address in a comment
        m = re.search(r'lea\s+.*\(%rip\),%rdx\s+#\s*([0-9a-f]+)', line)
        if m:
            array_addr = int(m.group(1), 16)
            continue

        # Fallback: lea with RIP-relative offset but no comment
        m = re.search(r'([0-9a-f]+):\s+lea\s+(-?0x[0-9a-f]+)\(%rip\),%rdx', line)
        if m:
            insn_addr = int(m.group(1), 16)
            offset = int(m.group(2), 16)
            # LEA is typically 7 bytes on x86_64
            array_addr = insn_addr + 7 + offset

    if array_addr is not None and n_methods is not None:
        return (array_addr, n_methods)
    return None


def _load_segments(so_path: str) -> list[tuple[int, int, int]]:
    """Return [(file_offset, vaddr, filesz), ...] for all LOAD segments."""
    if not hasattr(_load_segments, "_cache"):
        _load_segments._cache = {}
    if so_path in _load_segments._cache:
        return _load_segments._cache[so_path]

    segs = []
    out = run_cmd(["readelf", "-lW", so_path])  # -W = wide, single-line
    for line in out.splitlines():
        m = re.match(
            r'\s*LOAD\s+0x([0-9a-f]+)\s+0x([0-9a-f]+)\s+0x[0-9a-f]+\s+0x([0-9a-f]+)',
            line
        )
        if m:
            segs.append((int(m.group(1), 16), int(m.group(2), 16), int(m.group(3), 16)))
    _load_segments._cache[so_path] = segs
    return segs


def read_binary_section(so_path: str, vaddr: int, size: int) -> bytes | None:
    """Read `size` bytes from the ELF file at virtual address `vaddr`."""
    for file_off, seg_vaddr, filesz in _load_segments(so_path):
        if seg_vaddr <= vaddr < seg_vaddr + filesz:
            file_pos = file_off + (vaddr - seg_vaddr)
            with open(so_path, "rb") as f:
                f.seek(file_pos)
                return f.read(size)
    return None


def build_relocation_map(so_path: str) -> dict[int, tuple[int, str]]:
    """Parse ELF relocations to build addr -> (addend, symbol_name) map.

    Handles two relocation types:
      R_X86_64_RELATIVE  - base + addend (for string pointers within the same .so)
      R_X86_64_64        - symbol + addend (for external function pointers like JVM_*)
    """
    if not hasattr(build_relocation_map, "_cache"):
        build_relocation_map._cache = {}
    if so_path in build_relocation_map._cache:
        return build_relocation_map._cache[so_path]

    reloc_map = {}  # addr -> (resolved_vaddr, symbol_name)
    out = run_cmd(["readelf", "-rW", so_path])  # -W = wide, no truncation
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue

        rtype = parts[2]
        if rtype == "R_X86_64_RELATIVE":
            # Format: ADDR INFO R_X86_64_RELATIVE ADDEND  (4 fields)
            addend = int(parts[3], 16)
            reloc_map[addr] = (addend, "")
        elif rtype == "R_X86_64_64" and len(parts) >= 5:
            # Format: ADDR INFO R_X86_64_64 SYMVAL SYMNAME + ADDEND  (7 fields)
            sym = parts[4].split("@")[0]
            reloc_map[addr] = (0, sym)

    build_relocation_map._cache[so_path] = reloc_map
    return reloc_map


def build_symbol_table(so_path: str) -> dict[int, str]:
    """Build address -> symbol name map from nm output.

    Used to resolve internal function pointers (R_X86_64_RELATIVE addends)
    to their actual C/C++ function names (e.g., 0xb015f0 -> Unsafe_GetObject).
    """
    if not hasattr(build_symbol_table, "_cache"):
        build_symbol_table._cache = {}
    if so_path in build_symbol_table._cache:
        return build_symbol_table._cache[so_path]

    sym_map = {}
    out = run_cmd(["nm", so_path], timeout=60)
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[1] in ("t", "T"):
            try:
                addr = int(parts[0], 16)
                sym_map[addr] = parts[2]
            except ValueError:
                continue
    build_symbol_table._cache[so_path] = sym_map
    return sym_map


def read_cstring(so_path: str, vaddr: int, max_len: int = 256) -> str:
    """Read a null-terminated C string from the binary at virtual address."""
    data = read_binary_section(so_path, vaddr, max_len)
    if data is None:
        return "<unreadable>"
    end = data.find(b'\x00')
    if end >= 0:
        data = data[:end]
    return data.decode("utf-8", errors="replace")


_JAVA_IDENT_RE = re.compile(r"^[A-Za-z_$][A-Za-z0-9_$]*$")


def _resolve_pointer(so_path: str, slot_addr: int,
                     reloc_map: dict[int, tuple[int, str]]) -> tuple[int, str]:
    """Resolve a pointer at slot_addr.

    Tries ELF relocations first (correct for .data.rel.ro arrays where on-disk
    values are zero).  Falls back to reading the raw 8-byte value from the
    binary (correct for .data arrays like Netty / JFR where pointers are
    baked in at link time).

    Returns (vaddr_or_0, symbol_name).
    """
    if slot_addr in reloc_map:
        return reloc_map[slot_addr]
    # Direct-pointer fallback
    raw = read_binary_section(so_path, slot_addr, 8)
    if raw and len(raw) == 8:
        val = struct.unpack("<Q", raw)[0]
        if val != 0:
            return val, ""
    return 0, ""


def extract_methods_from_array(
    so_path: str, array_addr: int, n_methods: int,
    *, stop_on_invalid: bool = False,
) -> list[dict]:
    """Read JNINativeMethod structs from the binary.

    struct JNINativeMethod {
        char *name;       // 8 bytes
        char *signature;  // 8 bytes
        void *fnPtr;      // 8 bytes
    };

    Pointer resolution strategy:
      1. Check ELF relocations (for .data.rel.ro arrays where on-disk values
         are zero — libjava.so, libjvm.so Unsafe/MHN/Perf/WhiteBox).
      2. Fall back to reading raw pointer values from the binary (for .data
         arrays where pointers are baked in — Netty, JFR).

    When stop_on_invalid=True, stops at the first entry that doesn't look like
    a valid JNINativeMethod (used by Mode 4 when count is unknown).
    """
    reloc_map = build_relocation_map(so_path)
    sym_table = build_symbol_table(so_path)
    entry_size = 24  # 3 pointers on x86_64
    methods = []

    for i in range(n_methods):
        slot_base = array_addr + i * entry_size
        name_slot = slot_base
        sig_slot = slot_base + 8
        fn_slot = slot_base + 16

        # Resolve name pointer (relocation first, then direct)
        name_vaddr, _ = _resolve_pointer(so_path, name_slot, reloc_map)
        name = read_cstring(so_path, name_vaddr) if name_vaddr else ""

        # Resolve signature pointer
        sig_vaddr, _ = _resolve_pointer(so_path, sig_slot, reloc_map)
        sig = read_cstring(so_path, sig_vaddr) if sig_vaddr else ""

        # Validate: stop on clearly invalid entries
        if stop_on_invalid:
            if (not name or not _JAVA_IDENT_RE.match(name)
                    or not sig or not sig.startswith("(")):
                break

        if not name or name.startswith("<"):
            continue

        # Resolve function pointer: prefer symbol name from relocation,
        # then fall back to nm symbol table lookup for internal addresses
        fn_vaddr, fn_sym = _resolve_pointer(so_path, fn_slot, reloc_map)
        if fn_sym:
            fn_name = fn_sym  # external symbol (e.g. JVM_GetClassName)
        elif fn_vaddr:
            fn_name = sym_table.get(fn_vaddr, f"0x{fn_vaddr:x}")
        else:
            fn_name = "<unresolved>"

        methods.append({
            "name": name,
            "signature": sig,
            "fn_name": fn_name,
        })
    return methods


def jni_symbol_to_class(symbol: str) -> str:
    """Convert Java_java_lang_Class_registerNatives -> java.lang.Class"""
    if not symbol.startswith("Java_"):
        return symbol
    rest = symbol[5:]  # strip Java_
    # Remove _registerNatives suffix
    rest = re.sub(r'_registerNatives$', '', rest)
    return rest.replace('_', '.')


def enclosing_func_to_class(func_name: str) -> str:
    """Derive Java class name from the enclosing C function name.

    JVM_RegisterUnsafeMethods  -> sun.misc.Unsafe
    JVM_RegisterPerfMethods    -> sun.misc.Perf
    JVM_RegisterSignalMethods  -> sun.misc.Signal
    Generic fallback: strip JVM_Register and Methods suffix.
    """
    KNOWN = {
        # JDK 8
        "JVM_RegisterUnsafeMethods": "sun.misc.Unsafe",
        "JVM_RegisterPerfMethods": "jdk.internal.perf.Perf",
        "JVM_RegisterSignalMethods": "sun.misc.Signal",
        "JVM_RegisterMethodHandleMethods": "java.lang.invoke.MethodHandleNatives",
        "JVM_RegisterWhiteBoxMethods": "jdk.test.whitebox.WhiteBox",
        "jfr_register_natives": "jdk.jfr.internal.JVM",
        # JDK 11+  (jdk.internal.misc.Unsafe replaces sun.misc.Unsafe)
        "JVM_RegisterJDKInternalMiscUnsafeMethods": "jdk.internal.misc.Unsafe",
        # JDK 17+  (Foreign Function & Memory API, ScopedMemoryAccess, VectorSupport)
        "JVM_RegisterJDKInternalMiscScopedMemoryAccessMethods": "jdk.internal.misc.ScopedMemoryAccess",
        "JVM_RegisterNativeEntryPointMethods": "jdk.internal.foreign.abi.NativeEntryPoint",
        "JVM_RegisterProgrammableInvokerMethods": "jdk.internal.foreign.abi.ProgrammableInvoker",
        "JVM_RegisterProgrammableUpcallHandlerMethods": "jdk.internal.foreign.abi.ProgrammableUpcallHandler",
        "JVM_RegisterUpcallHandlerMethods": "jdk.internal.foreign.abi.UpcallLinker",
        "JVM_RegisterVectorSupportMethods": "jdk.internal.vm.vector.VectorSupport",
        # JDK 21+  (Continuations / virtual threads, UpcallLinker renamed)
        "JVM_RegisterContinuationMethods": "jdk.internal.vm.Continuation",
        "JVM_RegisterUpcallLinkerMethods": "jdk.internal.foreign.abi.UpcallLinker",
    }
    # Handle C++ mangled names
    if "JfrJniMethod" in func_name:
        return "jdk.jfr.internal.JVM"
    if "CONT_RegisterNativeMethods" in func_name:
        return "jdk.internal.vm.Continuation"
    if func_name in KNOWN:
        return KNOWN[func_name]
    # Try pattern: JVM_Register<Name>Methods -> <Name>
    m = re.match(r'JVM_Register(\w+?)Methods$', func_name)
    if m:
        return m.group(1)
    return func_name


def find_internal_register_natives_targets(so_path: str) -> list[int]:
    """Find addresses of all internal register_natives function variants in libjvm.so.

    Some JDK builds have two overloads:
      - 4-arg: register_natives(JNIEnv_*, _jclass*, JNINativeMethod const*, int)
      - 5-arg: register_natives(char const*, JNIEnv_*, _jclass*, JNINativeMethod const*, int)

    We need to scan callers of ALL variants; otherwise we miss registrations
    that go through one overload but not the other.
    """
    targets = []
    out = run_cmd(["nm", so_path])
    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[1] in ("t", "T"):
            if "register_natives" in parts[2] and "16register_natives" in parts[2]:
                targets.append(int(parts[0], 16))
    return targets


def _get_full_disassembly(so_path: str) -> str:
    """Get full disassembly (cached) since it's expensive."""
    if not hasattr(_get_full_disassembly, "_cache"):
        _get_full_disassembly._cache = {}
    if so_path in _get_full_disassembly._cache:
        return _get_full_disassembly._cache[so_path]
    out = run_cmd(
        ["objdump", "-d", "--no-show-raw-insn", so_path],
        timeout=300,
    )
    _get_full_disassembly._cache[so_path] = out
    return out


def _build_func_boundaries(lines: list[str]) -> list[tuple[int, str]]:
    """Build function boundary map from objdump lines.
    Returns [(addr, symbol_name), ...] sorted by addr."""
    boundaries = []
    for line in lines:
        fm = re.match(r'^([0-9a-f]+)\s+<(\S+?)>:', line)
        if fm:
            boundaries.append((int(fm.group(1), 16), fm.group(2)))
    return boundaries


def _find_enclosing_func(func_boundaries: list[tuple[int, str]], addr: int) -> str:
    """Find the enclosing function name for a given address."""
    for faddr, fname in reversed(func_boundaries):
        if faddr <= addr:
            return fname
    return ""


def _extract_array_and_count(lines: list[str], call_idx: int, lookback: int = 15) -> dict:
    """Scan backwards from call_idx to find LEA %rdx (array) and MOV %ecx (count).

    Handles four calling conventions:
      Standard:  LEA ...(%rip),%rdx + MOV $N,%ecx
      WhiteBox:  LEA ...(%rip),%rcx + MOV $N,%r8d
      Stack-copy (JFR): LEA -N(%rbp),%rdx + MOV $N,%ecx
        — array was copied to stack via rep movsq from LEA ...(%rip),%rsi
      Heap-copy (Netty): LEA ...(%rip),%rsi + rep movsq + MOV reg,%rcx + MOV $N,%r8d
        — array was malloc'd & modified; original source in %rsi
    """
    # Track standard (%rdx/%ecx) and WhiteBox (%rcx/%r8d) pairs separately
    # to avoid cross-contamination from unrelated instructions.
    rdx_array = None  # LEA ...(%rip),%rdx
    rdx_sym = ""
    ecx_count = None  # MOV $N,%ecx

    rcx_array = None  # LEA ...(%rip),%rcx  (WhiteBox)
    rcx_sym = ""
    r8d_count = None  # MOV $N,%r8d  (WhiteBox)

    # JFR stack-copy / Netty heap-copy pattern: rep movsq
    rsi_source = None  # %rsi value immediately before rep movsq (frozen on movsq)
    rsi_sym = ""
    rsi_pending = None  # latest LEA %rsi (unfrozen — may be overwritten)
    rsi_pending_sym = ""
    has_rep_movsq = False
    has_stack_lea_rdx = False

    for j in range(max(0, call_idx - lookback), call_idx):
        ln = lines[j].strip()

        # Standard: lea ...(%rip),%rdx  # addr <sym>
        m = re.search(r'lea\s+.*\(%rip\),%rdx\s+#\s*([0-9a-f]+)\s*(<(\S+)>)?', ln)
        if m:
            rdx_array = int(m.group(1), 16)
            rdx_sym = m.group(3) if m.group(3) else ""

        # Stack-copy detection (JFR): lea -N(%rbp),%rdx
        m = re.search(r'lea\s+-0x[0-9a-f]+\(%rbp\),%rdx', ln)
        if m:
            has_stack_lea_rdx = True

        # Track %rsi source — keep latest pending value
        m = re.search(r'lea\s+.*\(%rip\),%rsi\s+#\s*([0-9a-f]+)\s*(<(\S+)>)?', ln)
        if m:
            rsi_pending = int(m.group(1), 16)
            rsi_pending_sym = m.group(3) if m.group(3) else ""

        # On rep movsq, freeze the current %rsi as the array source.
        # Later %rsi values (e.g. for function call args) are irrelevant.
        if "rep movsq" in ln or "rep movs" in ln:
            has_rep_movsq = True
            if rsi_pending is not None:
                rsi_source = rsi_pending
                rsi_sym = rsi_pending_sym

        # Standard: mov $0xNN,%ecx or %cl or %cx  (last one wins — e.g.,
        # JFR has rep movsq count first, then actual method count).
        # Some compilers use %cl after rep movsq zeroes the upper bits.
        m = re.search(r'mov\s+\$0x([0-9a-f]+),%ecx', ln)
        if not m:
            m = re.search(r'mov\s+\$0x([0-9a-f]+),%cl\b', ln)
        if not m:
            m = re.search(r'mov\s+\$0x([0-9a-f]+),%cx\b', ln)
        if m:
            ecx_count = int(m.group(1), 16)

        # WhiteBox variant: lea ...(%rip),%rcx  # addr <sym>
        m = re.search(r'lea\s+.*\(%rip\),%rcx\s+#\s*([0-9a-f]+)\s*(<(\S+)>)?', ln)
        if m:
            rcx_array = int(m.group(1), 16)
            rcx_sym = m.group(3) if m.group(3) else ""

        # WhiteBox variant: mov $0xNN,%r8d
        m = re.search(r'mov\s+\$0x([0-9a-f]+),%r8d', ln)
        if m:
            r8d_count = int(m.group(1), 16)

    # Pick the best (array, count) pair.  More-specific patterns first:
    # 1. WhiteBox direct: %rcx array (direct LEA) + %r8d count
    # 2. Heap-copy (Netty): rep movsq from %rsi + %r8d count (no direct %rcx LEA)
    #    — must beat "standard" because in heap-copy context %rdx holds the
    #      className string and %ecx holds the movsq byte count, not method info.
    # 3. Stack-copy (JFR): rep movsq from %rsi + %ecx count + stack LEA %rdx
    # 4. Standard: %rdx array + %ecx count
    array_addr = None
    n_methods = None
    array_sym = ""

    if (has_rep_movsq and rsi_source is not None and r8d_count is not None):
        # Heap-copy: array copied to malloc'd buffer via rep movsq from %rsi,
        # then passed as %rcx via register move (not LEA).  Takes priority
        # over WhiteBox because %rcx may be reused for patching function
        # pointers into the copied array, not for the array address itself.
        array_addr, n_methods, array_sym = rsi_source, r8d_count, rsi_sym
    elif rcx_array is not None and r8d_count is not None:
        array_addr, n_methods, array_sym = rcx_array, r8d_count, rcx_sym
    elif (has_rep_movsq and has_stack_lea_rdx
          and rsi_source is not None and ecx_count is not None):
        array_addr, n_methods, array_sym = rsi_source, ecx_count, rsi_sym
    elif rdx_array is not None and ecx_count is not None:
        array_addr, n_methods, array_sym = rdx_array, ecx_count, rdx_sym

    return {"array_addr": array_addr, "n_methods": n_methods, "array_sym": array_sym,
            "rdx_addr": rdx_array}


def find_internal_callers(so_path: str, target_addr: int,
                          lookback: int = 15) -> list[dict]:
    """Find all call sites to target_addr in the binary and extract
    the LEA+MOV pairs that set up (array_addr, n_methods) arguments."""
    out = _get_full_disassembly(so_path)

    # First pass: find all call addresses to the target
    call_addrs = []
    for line in out.splitlines():
        if "call" in line and f"{target_addr:x}" in line:
            m = re.match(r'\s*([0-9a-f]+):', line)
            if m:
                call_addrs.append(int(m.group(1), 16))

    if not call_addrs:
        return []

    lines = out.splitlines()
    func_boundaries = _build_func_boundaries(lines)

    results = []
    for call_addr in call_addrs:
        call_idx = None
        for i, line in enumerate(lines):
            if line.strip().startswith(f"{call_addr:x}:"):
                call_idx = i
                break
        if call_idx is None:
            continue

        enclosing_func = _find_enclosing_func(func_boundaries, call_addr)
        info = _extract_array_and_count(lines, call_idx, lookback=lookback)

        if info["array_addr"] is not None and info["n_methods"] is not None:
            results.append({
                "call_addr": call_addr,
                "array_addr": info["array_addr"],
                "array_sym": info["array_sym"],
                "n_methods": info["n_methods"],
                "enclosing_func": enclosing_func,
                "rdx_addr": info.get("rdx_addr"),
            })

    return results


def find_jni_register_natives_callers(so_path: str) -> list[dict]:
    """Mode 3: Find all indirect calls through the JNI function table at offset 0x6b8.

    Pattern:  call *0x6b8(%rax)   — RegisterNatives via (*env)->RegisterNatives(...)
    Args are in standard x86_64 calling convention:
        %rdx = JNINativeMethod* methods
        %ecx = jint nMethods

    Also finds calls to WhiteBox::register_methods wrapper which uses
    %rcx = methods, %r8d = nMethods (5-arg function).
    """
    out = _get_full_disassembly(so_path)
    lines = out.splitlines()
    func_boundaries = _build_func_boundaries(lines)

    # Find all call *0x6b8( lines — JNI RegisterNatives
    jni_call_indices = []
    # Find all calls to WhiteBox::register_methods
    wb_call_indices = []
    for i, line in enumerate(lines):
        stripped = line.strip()
        if "call" in stripped and "0x6b8(" in stripped:
            jni_call_indices.append(i)
        elif "call" in stripped and "register_methods" in stripped and "WhiteBox" in stripped:
            wb_call_indices.append(i)

    results = []
    seen_arrays = set()

    # Process JNI indirect calls (standard %rdx/%ecx args)
    for call_idx in jni_call_indices:
        line = lines[call_idx].strip()
        m = re.match(r'([0-9a-f]+):', line)
        if not m:
            continue
        call_addr = int(m.group(1), 16)
        enclosing_func = _find_enclosing_func(func_boundaries, call_addr)

        # Skip wrapper functions whose args come from parameters, not inline LEA/MOV:
        #  - WhiteBox::register_methods internal loop (registers 1 at a time)
        #  - netty_unix_util_register_natives and similar wrappers
        # Note: "register_natives" (underscore) won't match Java_*_registerNatives (camelCase)
        if "register_methods" in enclosing_func or "register_natives" in enclosing_func:
            continue

        info = _extract_array_and_count(lines, call_idx)
        if info["array_addr"] is not None and info["n_methods"] is not None:
            aa = info["array_addr"]
            if aa not in seen_arrays:
                seen_arrays.add(aa)
                results.append({
                    "call_addr": call_addr,
                    "array_addr": aa,
                    "array_sym": info["array_sym"],
                    "n_methods": info["n_methods"],
                    "enclosing_func": enclosing_func,
                })

    # Process WhiteBox::register_methods calls (%rcx/%r8d args)
    for call_idx in wb_call_indices:
        line = lines[call_idx].strip()
        m = re.match(r'([0-9a-f]+):', line)
        if not m:
            continue
        call_addr = int(m.group(1), 16)
        enclosing_func = _find_enclosing_func(func_boundaries, call_addr)

        info = _extract_array_and_count(lines, call_idx)
        if info["array_addr"] is not None and info["n_methods"] is not None:
            aa = info["array_addr"]
            if aa not in seen_arrays:
                seen_arrays.add(aa)
                results.append({
                    "call_addr": call_addr,
                    "array_addr": aa,
                    "array_sym": info["array_sym"],
                    "n_methods": info["n_methods"],
                    "enclosing_func": enclosing_func,
                })

    return results


def find_exported_register_wrappers(so_path: str) -> list[tuple[str, int]]:
    """Find *register_natives wrapper functions and their call-target addresses.

    Netty (and similar libraries) register JNI methods through wrapper functions
    like netty_unix_util_register_natives.  In some builds the wrapper is
    exported (nm -D shows 'T'), in others it's a local symbol ('t' in nm).

    When exported, callers reference the PLT stub (e.g. call 0x3c10 <...@plt>).
    When local, callers call the function address directly.

    Excludes Java_*_registerNatives (handled by Mode 1).
    """
    candidates = {}  # symbol_name -> actual_addr

    # Step 1a: find candidate symbols via nm -D (exported)
    nm_out = run_cmd(["nm", "-D", so_path])
    for line in nm_out.splitlines():
        parts = line.strip().split()
        if len(parts) == 3 and parts[1] == "T":
            sym = parts[2].split("@@")[0]
            if "register_natives" in sym and not sym.startswith("Java_"):
                candidates[sym] = int(parts[0], 16)

    # Step 1b: also scan full symbol table for local 't' symbols
    # (some Netty builds statically link the wrapper, making it local)
    if not candidates:
        nm_out = run_cmd(["nm", so_path])
        for line in nm_out.splitlines():
            parts = line.strip().split()
            if len(parts) == 3 and parts[1] in ("t", "T"):
                sym = parts[2]
                if "register_natives" in sym and not sym.startswith("Java_"):
                    candidates[sym] = int(parts[0], 16)

    if not candidates:
        return []

    # Step 2: find PLT stub addresses from the disassembly (only for exported)
    disasm = _get_full_disassembly(so_path)
    plt_addrs = {}  # symbol_name -> plt_addr
    for line in disasm.splitlines():
        for sym in candidates:
            # Match: 0000000000003c10 <netty_unix_util_register_natives@plt>:
            if f"<{sym}@plt>:" in line:
                m = re.match(r'^([0-9a-f]+)\s+<', line)
                if m:
                    plt_addrs[sym] = int(m.group(1), 16)

    results = []
    for sym, actual_addr in candidates.items():
        # Prefer PLT address (what callers reference); fall back to actual
        addr = plt_addrs.get(sym, actual_addr)
        results.append((sym, addr))

    return results


_CLASS_PATH_RE = re.compile(r"^[a-zA-Z_$][a-zA-Z0-9_$/]*$")


def _read_class_from_rdx(so_path: str, rdx_addr: int | None) -> str | None:
    """Read the %rdx target as a JVM class name string.

    Netty wrapper callers pass the className as %rdx in JVM internal format
    (e.g. "io/netty/channel/unix/FileDescriptor").  This function reads the
    string from the binary and converts to dotted form.

    Returns None if the address is invalid or the string doesn't look like
    a class path.
    """
    if not rdx_addr:
        return None
    s = read_cstring(so_path, rdx_addr)
    if not s or s.startswith("<") or "/" not in s:
        return None
    if not _CLASS_PATH_RE.match(s):
        return None
    return s.replace("/", ".")


def _probe_method_array(so_path: str, vaddr: int, sample: int = 3) -> int:
    """Test if vaddr looks like a valid JNINativeMethod array.

    Returns the number of leading valid entries (out of `sample`).
    A valid entry has: name = Java identifier, signature starts with '('.
    """
    reloc_map = build_relocation_map(so_path)
    valid = 0
    for i in range(sample):
        slot = vaddr + i * 24
        name_va, _ = _resolve_pointer(so_path, slot, reloc_map)
        sig_va, _ = _resolve_pointer(so_path, slot + 8, reloc_map)
        name = read_cstring(so_path, name_va) if name_va else ""
        sig = read_cstring(so_path, sig_va) if sig_va else ""
        if name and _JAVA_IDENT_RE.match(name) and sig and sig.startswith("("):
            valid += 1
        elif i == 0:
            return 0  # first entry must be valid
    return valid


# Map of known array symbol names / patterns to Java class names.
# None means "derive from .so filename".
_KNOWN_ARRAY_SYMBOLS: dict[str, str | None] = {
    "fixed_method_table": None,
    "statically_referenced_fixed_method_table": None,
    "method_table": None,
}

# Regex patterns for C++ mangled static-local method arrays
_MANGLED_ARRAY_PATTERNS = [
    # JfrJniMethodRegistration constructor static local
    (re.compile(r"_ZZ.*JfrJniMethod.*method"), "jdk.jfr.internal.JVM"),
    # Generic static local method arrays in *Register* functions
    (re.compile(r"_ZZ.*Register.*E\d*method"), None),
]


def _derive_java_class_for_symbol(sym_name: str, so_basename: str) -> str:
    """Derive the Java class name for a Mode 4 array symbol.

    Uses a hierarchy: mangled pattern -> .so filename heuristics -> symbol name.
    """
    # Check mangled patterns
    for pat, cls in _MANGLED_ARRAY_PATTERNS:
        if pat.search(sym_name):
            if cls:
                return cls

    # Netty: derive from .so filename
    so_lower = so_basename.lower()
    if "netty" in so_lower:
        # Epoll
        if "epoll" in so_lower:
            if "statically_referenced" in sym_name:
                return "io.netty.channel.epoll.NativeStaticallyReferencedJniMethods"
            return "io.netty.channel.epoll.Native"
        # io_uring
        if "io_uring" in so_lower or "uring" in so_lower:
            if "statically_referenced" in sym_name:
                return "io.netty.channel.uring.NativeStaticallyReferencedJniMethods"
            return "io.netty.channel.uring.Native"
        # tcnative (SSL)
        if "tcnative" in so_lower:
            return "io.netty.internal.tcnative.NativeStaticallyReferencedJniMethods"
        # Generic netty
        return f"netty.native ({so_basename})"

    # Fallback
    return sym_name


def find_method_arrays_by_symbol(so_path: str, seen_arrays: set[int]) -> list[dict]:
    """Mode 4: Find JNINativeMethod arrays by scanning nm for known symbol names.

    Handles:
    - Netty: fixed_method_table, statically_referenced_fixed_method_table
    - JFR: static local arrays in JfrJniMethodRegistration constructor
    - Generic: any data symbol matching known patterns

    Probes each candidate to verify it's a valid array, then reads until
    the first invalid entry (since the exact count is unknown).
    """
    MAX_METHODS = 200  # upper bound per array to prevent runaway reads

    out = run_cmd(["nm", "-n", so_path], timeout=60)
    candidates: list[tuple[int, str]] = []  # (addr, symbol_name)

    for line in out.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        sym_type = parts[1]
        sym_name = parts[2]
        # Only data section symbols (d/D = local/global data, r/R = read-only data)
        if sym_type not in ("d", "D", "r", "R"):
            continue
        try:
            addr = int(parts[0], 16)
        except ValueError:
            continue

        # Check against known symbol names
        base_name = sym_name.rsplit(".", 1)[0]  # strip .NNN suffix if any
        if base_name in _KNOWN_ARRAY_SYMBOLS:
            candidates.append((addr, sym_name))
            continue

        # Check mangled patterns
        for pat, _ in _MANGLED_ARRAY_PATTERNS:
            if pat.search(sym_name):
                candidates.append((addr, sym_name))
                break

    if not candidates:
        return []

    so_basename = os.path.basename(so_path)
    results = []

    for addr, sym_name in candidates:
        if addr in seen_arrays:
            continue

        # Probe: first 3 entries must look like valid JNINativeMethod
        if _probe_method_array(so_path, addr) < 2:
            continue

        seen_arrays.add(addr)
        methods = extract_methods_from_array(
            so_path, addr, MAX_METHODS, stop_on_invalid=True
        )
        if not methods:
            continue

        java_class = _derive_java_class_for_symbol(sym_name, so_basename)
        results.append({
            "so_file": so_basename,
            "symbol": sym_name,
            "java_class": java_class,
            "array_addr": f"0x{addr:x}",
            "n_methods": len(methods),
            "methods": methods,
        })

    return results


def process_so_file(so_path: str) -> list[dict]:
    """Extract all RegisterNatives tables from a single .so file."""
    all_results = []

    # --- Mode 1: Exported Java_*_registerNatives symbols ---
    symbols = find_register_natives_symbols(so_path)
    for sym_name, sym_addr in symbols:
        disasm = disassemble_function(so_path, sym_addr)
        parsed = parse_register_natives_call(disasm, sym_addr)
        if parsed is None:
            print(f"  WARN: Could not parse {sym_name} at 0x{sym_addr:x}", file=sys.stderr)
            continue

        array_addr, n_methods = parsed
        methods = extract_methods_from_array(so_path, array_addr, n_methods)
        java_class = jni_symbol_to_class(sym_name)

        all_results.append({
            "so_file": os.path.basename(so_path),
            "symbol": sym_name,
            "java_class": java_class,
            "array_addr": f"0x{array_addr:x}",
            "n_methods": n_methods,
            "methods": methods,
        })

    # --- Mode 2: Internal register_natives in libjvm.so ---
    if not symbols:
        seen_arrays = set()

        targets = find_internal_register_natives_targets(so_path)
        if targets:
            for target in targets:
                print(f"  Found internal register_natives at 0x{target:x}", file=sys.stderr)
            print(f"  Scanning for call sites (this may take a moment)...", file=sys.stderr)
            for target in targets:
                callers = find_internal_callers(so_path, target)
                for info in callers:
                    aa = info["array_addr"]
                    if aa in seen_arrays:
                        continue
                    seen_arrays.add(aa)
                    methods = extract_methods_from_array(so_path, aa, info["n_methods"])
                    sym = info.get("array_sym", "")
                    enc = info.get("enclosing_func", "")
                    java_class = enclosing_func_to_class(enc) if enc else "unknown"
                    all_results.append({
                        "so_file": os.path.basename(so_path),
                        "symbol": sym or f"call@0x{info['call_addr']:x}",
                        "java_class": java_class,
                        "array_addr": f"0x{aa:x}",
                        "n_methods": info["n_methods"],
                        "methods": methods,
                    })

        # --- Mode 3: JNI function table indirect calls: call *0x6b8(%rax) ---
        print(f"  Scanning for JNI RegisterNatives calls (call *0x6b8)...", file=sys.stderr)
        jni_callers = find_jni_register_natives_callers(so_path)
        for info in jni_callers:
            aa = info["array_addr"]
            if aa in seen_arrays:
                continue
            seen_arrays.add(aa)
            methods = extract_methods_from_array(so_path, aa, info["n_methods"])
            sym = info.get("array_sym", "")
            enc = info.get("enclosing_func", "")
            java_class = enclosing_func_to_class(enc) if enc else "unknown"
            all_results.append({
                "so_file": os.path.basename(so_path),
                "symbol": sym or f"jni_call@0x{info['call_addr']:x}",
                "java_class": java_class,
                "array_addr": f"0x{aa:x}",
                "n_methods": info["n_methods"],
                "methods": methods,
            })

    # --- Mode 5: Wrapper function callers (Netty-style register_natives) ---
    # Netty registers natives through netty_unix_util_register_natives(env,
    # prefix, className, methods, count).  Callers set up %rcx = methods,
    # %r8d = count (WhiteBox convention), and %rdx = className string.
    wrappers = find_exported_register_wrappers(so_path)
    if wrappers:
        # Build seen_arrays from all results so far (Modes 1-3)
        m5_seen = set()
        for r in all_results:
            addr_str = r.get("array_addr", "")
            if addr_str.startswith("0x"):
                m5_seen.add(int(addr_str, 16))

        for wrapper_name, wrapper_addr in wrappers:
            print(f"  Mode 5: tracing callers of {wrapper_name} "
                  f"(0x{wrapper_addr:x})...", file=sys.stderr)
            callers = find_internal_callers(so_path, wrapper_addr, lookback=60)
            for info in callers:
                aa = info["array_addr"]
                if aa in m5_seen:
                    continue
                m5_seen.add(aa)
                methods = extract_methods_from_array(so_path, aa, info["n_methods"])
                if not methods:
                    continue

                # Read className from %rdx (3rd arg to the wrapper)
                java_class = _read_class_from_rdx(so_path, info.get("rdx_addr"))
                if not java_class:
                    enc = info.get("enclosing_func", "")
                    java_class = enclosing_func_to_class(enc) if enc else "unknown"

                all_results.append({
                    "so_file": os.path.basename(so_path),
                    "symbol": f"wrapper_call@0x{info['call_addr']:x}",
                    "java_class": java_class,
                    "array_addr": f"0x{aa:x}",
                    "n_methods": info["n_methods"],
                    "methods": methods,
                })

    # --- Mode 4: Symbol-based array discovery (JFR, Netty, generic) ---
    # Runs on ALL files as a catch-all for arrays missed by Modes 1-3/5.
    # Uses known symbol names (fixed_method_table, JfrJniMethod, etc.)
    # and probes data to verify valid JNINativeMethod entries.
    mode4_seen = set()
    # Collect all array addresses already found by Modes 1-3/5
    for r in all_results:
        addr_str = r.get("array_addr", "")
        if addr_str.startswith("0x"):
            mode4_seen.add(int(addr_str, 16))

    print(f"  Scanning for named method arrays (Mode 4)...", file=sys.stderr)
    mode4_results = find_method_arrays_by_symbol(so_path, mode4_seen)
    all_results.extend(mode4_results)

    return all_results


def write_mapping_file(output_path: str, all_entries: list[dict]):
    """Write results in pipe-delimited mapping format:
    so_file|java_class.method|signature|native_symbol|BIN_SCAN

    Deduplicates on (so_file, class.method, signature), keeping the first
    occurrence (newest version variant from the registration tables).
    """
    seen = set()
    lines = []
    for entry in all_entries:
        so_file = entry["so_file"]
        java_class = entry["java_class"]
        for m in entry["methods"]:
            method_name = m["name"]
            sig = m["signature"]
            fn = m["fn_name"]
            key = (so_file, f"{java_class}.{method_name}", sig)
            if key in seen:
                continue
            seen.add(key)
            lines.append(f"{so_file}|{java_class}.{method_name}|{sig}|{fn}|BIN_SCAN")

    # Sort by so_file, then java_class.method
    lines.sort()

    with open(output_path, "w") as f:
        f.write("# JVM native method bindings extracted from binary (RegisterNatives tables)\n")
        f.write("# Format: library|java_class.method|signature|native_symbol|confidence\n")
        f.write("#\n")
        for line in lines:
            f.write(line + "\n")

    print(f"\n  Wrote {len(lines)} mappings to {output_path}", file=sys.stderr)


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description="Extract JNINativeMethod[] tables from .so binaries"
    )
    parser.add_argument("so_files", nargs="+", metavar="FILE.so",
                        help="One or more .so files to analyze")
    parser.add_argument("-o", "--output", metavar="FILE",
                        help="Write pipe-delimited mapping file (BIN_SCAN format)")
    args = parser.parse_args()

    grand_total = 0
    all_entries = []

    for so_path in args.so_files:
        if not os.path.isfile(so_path):
            print(f"SKIP: {so_path} not found", file=sys.stderr)
            continue

        results = process_so_file(so_path)
        if not results:
            continue

        all_entries.extend(results)

        print(f"\n{'='*80}")
        print(f"  {so_path}")
        print(f"{'='*80}")

        for entry in results:
            n = len(entry["methods"])
            grand_total += n
            print(f"\n  {entry['java_class']} ({n} methods)")
            print(f"  symbol: {entry['symbol']}")
            print(f"  array:  {entry['array_addr']}  count: {entry['n_methods']}")
            print(f"  {'─'*74}")

            for m in entry["methods"]:
                fn = m["fn_name"]
                print(f"    {m['name']}{m['signature']}  ->  {fn}")

    print(f"\n{'='*80}")
    print(f"  Total: {grand_total} registered native methods")
    print(f"{'='*80}")

    if args.output:
        write_mapping_file(args.output, all_entries)


if __name__ == "__main__":
    main()
