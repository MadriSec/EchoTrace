package com.example.app;

import com.example.native_lib.MyKernel32;

/**
 * Application that uses custom StdCallLibrary interface.
 *
 * Expected detection:
 *   lib=kernel32, symbol=Beep, interface=MyKernel32
 *   lib=kernel32, symbol=GetCurrentProcessId, interface=MyKernel32
 *   lib=kernel32, symbol=SetConsoleTitle, interface=MyKernel32
 */
public class WinApp {

    public void makeBeep() {
        MyKernel32.INSTANCE.Beep(750, 300);  // <-- Should detect!
    }

    public int getPid() {
        return MyKernel32.INSTANCE.GetCurrentProcessId();  // <-- Should detect!
    }

    public void setTitle(String title) {
        MyKernel32.INSTANCE.SetConsoleTitle(title);  // <-- Should detect!
    }

    public static void main(String[] args) {
        WinApp app = new WinApp();
        app.makeBeep();
        System.out.println("PID: " + app.getPid());
        app.setTitle("My App");
    }
}
