package com.echotrace.app.bytecode_new.crossjdk;

/**
 * Minimal "application" bytecode used by cross-JDK tests: declares JDK JNI-style
 * natives and calls a well-known JDK static native so {@link com.echotrace.app.bytecode_new.PrototypeFinal}
 * can load {@code java.lang.System} from a version-specific {@code --runtime} jar.
 */
public final class DemoNativeApplication {

    private DemoNativeApplication() {}

    /** Application JNI entry (would live in app-provided {@code .so}); not implemented for tests. */
    public static native void applicationPing();

    /**
     * Pulls in {@link Object#hashCode()} (JNI in {@code java.lang.Object}) so Flow 2 loads
     * JDK classes from the staged runtime JAR; stable across JDK 8–25.
     */
    public static void touchJdkNative() {
        new Object().hashCode();
    }
}
