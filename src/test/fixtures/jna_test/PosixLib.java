package com.example.native_lib;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * A second JNA interface extending Library directly (not CLib).
 *
 * Tests:
 *   - Different interface name (PosixLib vs CLib)
 *   - Native.load(null, ...) which means "default C library"
 *     (libc.so on Linux, System on macOS, msvcrt on Windows)
 */
public interface PosixLib extends Library {

    // null library name = default C library
    PosixLib INSTANCE = Native.load(null, PosixLib.class);

    int getpid();

    int getuid();
}
