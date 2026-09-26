// com.example.app.Main
package com.example.app;
public class Main {
    public static void main(String[] args) {
        Helper.run();                 // target class call
        com.example.dep.Util.ping();  // dependency call
    }
}
class Helper {
    public static void run() {}
}

