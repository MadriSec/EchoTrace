package com.example.native_lib;

import com.sun.jna.Library;
import com.sun.jna.Native;

/**
 * JNA interface for C library functions.
 * This interface extends com.sun.jna.Library.
 *
 * The INSTANCE field is loaded via Native.load("c", CLib.class)
 * which tells JNA to load the "c" library (libc.so on Linux, msvcrt.dll on Windows).
 */
public interface CLib extends Library {

    // Static field initialized with Native.load() - this is the JNA pattern
    CLib INSTANCE = Native.load("c", CLib.class);

    // Native method declarations - method name = symbol name
    int strlen(String s);

    int getpid();

    int getuid();
}
