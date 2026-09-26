package com.example.native_lib;

import com.sun.jna.Native;
import com.sun.jna.win32.StdCallLibrary;

/**
 * Custom JNA interface extending StdCallLibrary (for Windows stdcall convention).
 * This proves the detector handles:
 *   MyKernel32 → StdCallLibrary → Library
 */
public interface MyKernel32 extends StdCallLibrary {

    // Load kernel32.dll via Native.load
    MyKernel32 INSTANCE = Native.load("kernel32", MyKernel32.class);

    // Custom native method declarations
    boolean Beep(int dwFreq, int dwDuration);

    int GetCurrentProcessId();

    boolean SetConsoleTitle(String title);
}
