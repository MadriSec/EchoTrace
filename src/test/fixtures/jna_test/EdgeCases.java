package com.example.app;

import com.example.native_lib.CLib;
import com.example.native_lib.PosixLib;
import com.sun.jna.Native;

/**
 * Edge case test class for JnaIfaceDetector.
 *
 * Tests patterns beyond the standard CLib.INSTANCE usage:
 *   1. Different field name (INSTANCE2) on CLib
 *   2. Different interface (PosixLib) with null library name
 *   3. Local variable instead of static field
 */
public class EdgeCases {

    // Edge case #3: different field name (not "INSTANCE")
    // The detector should still resolve lib="c" via field taint tracking
    private static final CLib INSTANCE2 = Native.load("c", CLib.class);

    /**
     * Calls via INSTANCE2 (different field name).
     * Expected: lib=c, symbol=getpid, interface=CLib
     */
    public int getpidViaInstance2() {
        return INSTANCE2.getpid();
    }

    /**
     * Another call via INSTANCE2 to verify multiple methods work.
     * Expected: lib=c, symbol=strlen, interface=CLib
     */
    public int strlenViaInstance2(String s) {
        return INSTANCE2.strlen(s);
    }

    /**
     * Edge case #4: different interface (PosixLib instead of CLib).
     * PosixLib.INSTANCE = Native.load(null, PosixLib.class)
     * Expected: lib=<null:default-c-lib>, symbol=getpid, interface=PosixLib
     */
    public int getpidViaPosixLib() {
        return PosixLib.INSTANCE.getpid();
    }

    /**
     * Edge case #5: local variable instead of static field.
     * The detector tracks taint through local variables too.
     * Expected: lib=c, symbol=strlen, interface=CLib
     */
    public int localVarUsage(String s) {
        CLib lib = Native.load("c", CLib.class);
        return lib.strlen(s);
    }

    public static void main(String[] args) {
        EdgeCases e = new EdgeCases();
        System.out.println("getpid via INSTANCE2: " + e.getpidViaInstance2());
        System.out.println("strlen via INSTANCE2: " + e.strlenViaInstance2("hello"));
        System.out.println("getpid via PosixLib: " + e.getpidViaPosixLib());
        System.out.println("strlen via local var: " + e.localVarUsage("hello"));
    }
}
