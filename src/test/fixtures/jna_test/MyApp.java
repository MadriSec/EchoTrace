package com.example.app;

import com.example.native_lib.CLib;

/**
 * Application class that uses JNA interface.
 *
 * This class is in a DIFFERENT package (and will be in a different JAR)
 * than the CLib interface.
 *
 * Expected detection:
 *   callerSig:  <com.example.app.MyApp: int getStringLength(java.lang.String)>
 *   lib:        c
 *   symbol:     strlen
 *   interface:  com.example.native_lib.CLib
 *   calleeSig:  <com.example.native_lib.CLib: int strlen(java.lang.String)>
 *   callerJar:  myapp.jar
 *   calleeJar:  mylib.jar
 */
public class MyApp {

    /**
     * Calls CLib.INSTANCE.strlen() - this is what we want to detect.
     */
    public int getStringLength(String s) {
        return CLib.INSTANCE.strlen(s);  // <-- JNA interface call!
    }

    /**
     * Another JNA call - getpid()
     */
    public int getCurrentProcessId() {
        return CLib.INSTANCE.getpid();   // <-- JNA interface call!
    }

    /**
     * Another JNA call - getuid()
     */
    public int getCurrentUserId() {
        return CLib.INSTANCE.getuid();   // <-- JNA interface call!
    }

    public static void main(String[] args) {
        MyApp app = new MyApp();
        System.out.println("Length of 'hello': " + app.getStringLength("hello"));
        System.out.println("Process ID: " + app.getCurrentProcessId());
        System.out.println("User ID: " + app.getCurrentUserId());
    }
}
