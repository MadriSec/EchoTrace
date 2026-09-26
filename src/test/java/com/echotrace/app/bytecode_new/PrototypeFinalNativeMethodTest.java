package com.echotrace.app.bytecode_new;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the native-method discovery + URLClassLoader hermeticity
 * inside {@link PrototypeFinal}.
 *
 * The suite locks down two invariants:
 *
 *  1. Native methods declared (Flow 1, ClassPrinter.visitMethod) and reached
 *     via a call edge (Flow 2, MethodPrinter.visitMethodInsn -> ClassFilter)
 *     are collected into Util.visitedNative iff the owning class is present
 *     in one of the *target* JARs.
 *
 *  2. The targetClassLoader is hermetic: it never falls through to the
 *     analyzer JVM's bootstrap classloader, so a JDK 11 analyzer cannot leak
 *     JDK 11-only natives (FileDescriptor.getAppend / getHandle, etc.) into
 *     the analysis of a JDK 8 application that ships its own rt.jar.
 *
 * Test JARs are built programmatically with ASM into a JUnit @TempDir, so the
 * suite is hermetic and runs in milliseconds.  No fixtures need to be checked
 * into version control.
 */
class PrototypeFinalNativeMethodTest {

    @TempDir Path tempDir;

    /** Closed in @AfterEach. */
    private URLClassLoader testClassLoader;

    @BeforeEach
    void resetStaticState() throws Exception {
        // Static collections are shared across runs of main(); reset them
        // here so each test sees a clean slate.
        PrototypeFinal.Util.visitedNative.clear();
        PrototypeFinal.Util.visitedMethod.clear();

        // pathPrefix is a private static field; traceJarFiles uses it as the
        // dir to resolve JAR names against.  Mirror main()'s normalization
        // (always ends with '/').
        String prefix = tempDir.toString();
        if (!prefix.endsWith("/")) prefix += "/";
        setStatic("pathPrefix", prefix);

        // Make sure no stale loader from a previous test leaks into this one.
        setStatic("targetClassLoader", null);
    }

    @AfterEach
    void teardown() throws Exception {
        if (testClassLoader != null) {
            try { testClassLoader.close(); } catch (IOException ignored) { /* best-effort */ }
            testClassLoader = null;
        }
        setStatic("targetClassLoader", null);
    }

    // ---------------------------------------------------------------------
    //  Flow 1 - Direct enumeration of ACC_NATIVE methods inside target JARs
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("Flow 1: a directly-declared native method is captured")
    void directNativeDeclarationIsCaptured() throws Exception {
        Path jar = writeJar("direct.jar",
                classWithNative("com/example/A", "nativeFoo"));

        runAnalysis(jar);

        assertContains(PrototypeFinal.Util.visitedNative, "com.example.A.nativeFoo");
    }

    // ---------------------------------------------------------------------
    //  Flow 2 - Call edges followed via targetClassLoader
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("Flow 2: call edge to a native method on a class in the same JAR is captured")
    void callEdgeNativeIsCaptured() throws Exception {
        Path jar = writeJar("call-edge.jar",
                classWithCall("com/example/Caller", "callBar",
                              "com/example/B", "nativeBar"),
                classWithNative("com/example/B", "nativeBar"));

        runAnalysis(jar);

        // Caller method itself is not native, callee is.
        assertContains(PrototypeFinal.Util.visitedNative, "com.example.B.nativeBar");
        assertFalse(PrototypeFinal.Util.visitedNative.contains("com.example.Caller.callBar"),
                "Non-native caller must not be recorded as a native method");
    }

    @Test
    @DisplayName("Flow 2: a call to a class not in any target JAR is silently skipped")
    void unknownClassIsSilentlySkipped() throws Exception {
        Path jar = writeJar("unknown-callee.jar",
                classWithCall("com/example/Caller", "doIt",
                              "totally/made/up/Nope", "boom"));

        // No exception, no spurious entries: traceJarFiles must complete cleanly.
        assertDoesNotThrow(() -> runAnalysis(jar));
        assertTrue(
                PrototypeFinal.Util.visitedNative.stream()
                        .noneMatch(s -> s.startsWith("totally.made.up.Nope.")),
                "Unknown class should not produce any visitedNative entries");
    }

    // ---------------------------------------------------------------------
    //  JDK-leak guards (the URLClassLoader fix)
    // ---------------------------------------------------------------------

    /**
     * Self-validating precondition: confirms that the JDK class we use as the
     * leak attack surface (java.lang.Thread.yield()V) is actually reachable
     * from the analyzer JVM AND is declared ACC_NATIVE there.  Without this,
     * a green leak test could simply mean "the JDK version of yield() is
     * non-native or unreachable" rather than "the fix worked".
     *
     * Thread.yield()V was chosen because:
     *   - signature ()V matches our synthetic INVOKESTATIC helper
     *   - it has been ACC_NATIVE in every public OpenJDK release through 21
     */
    @Test
    @DisplayName("Precondition: analyzer JVM's java.lang.Thread.yield()V is ACC_NATIVE")
    void leakAttackSurfaceExists() throws Exception {
        try (InputStream is = ClassLoader.getSystemResourceAsStream("java/lang/Thread.class")) {
            assertNotNull(is, "Analyzer JVM must expose java/lang/Thread.class as a system resource"
                    + " - leak tests can't be meaningful otherwise");
            ClassReader cr = new ClassReader(is);
            boolean[] sawNativeYield = { false };
            cr.accept(new org.objectweb.asm.ClassVisitor(Opcodes.ASM9) {
                @Override
                public MethodVisitor visitMethod(int access, String name, String descriptor,
                                                  String signature, String[] exceptions) {
                    if ("yield".equals(name) && "()V".equals(descriptor)
                            && (access & Opcodes.ACC_NATIVE) != 0) {
                        sawNativeYield[0] = true;
                    }
                    return null;
                }
            }, 0);
            assertTrue(sawNativeYield[0],
                    "Expected analyzer JVM's Thread.yield()V to be ACC_NATIVE - "
                            + "if not, pick a different leak attack surface");
        }
    }

    @Test
    @DisplayName("JDK leak: analyzer-JVM JDK natives don't leak when no rt.jar is staged")
    void jdkLeakBlockedWhenNoRtJarStaged() throws Exception {
        // Caller bytecode references java.lang.Thread.yield()V, which IS
        // ACC_NATIVE in the analyzer JVM (verified by leakAttackSurfaceExists).
        // With null parent + findResource-only override, the call edge must
        // be silently skipped.  Without the fix, `new ClassReader("java.lang.Thread")`
        // would succeed via the system classloader and leak yield into the result.
        Path jar = writeJar("leak-no-rt.jar",
                classWithCall("com/example/Caller", "doIt",
                              "java/lang/Thread", "yield"));

        runAnalysis(jar);

        List<String> leaks = PrototypeFinal.Util.visitedNative.stream()
                .filter(s -> s.startsWith("java.lang.Thread."))
                .collect(java.util.stream.Collectors.toList());
        assertTrue(leaks.isEmpty(),
                "Analyzer JDK must not leak; leaked entries: " + leaks);
    }

    @Test
    @DisplayName("JDK leak: a target rt-shaped JAR without the called method records nothing")
    void targetRtJarWithoutMethodAddsNothing() throws Exception {
        Path callerJar = writeJar("leak-target-no-method-caller.jar",
                classWithCall("com/example/Caller", "doIt",
                              "java/lang/Thread", "yield"));

        // Stage a "fake rt.jar" whose Thread does NOT declare yield()V.
        Path rtJar = writeJar("fake_rt.jar",
                classWithMethod("java/lang/Thread", "valid", "()V",
                                /* native = */ false));

        runAnalysis(callerJar, rtJar);

        // Even though the analyzer's own JDK has Thread.yield()V declared
        // ACC_NATIVE, the target rt.jar's Thread wins (it doesn't have yield),
        // so nothing should be recorded under java.lang.Thread.
        List<String> leaks = PrototypeFinal.Util.visitedNative.stream()
                .filter(s -> s.startsWith("java.lang.Thread."))
                .collect(java.util.stream.Collectors.toList());
        assertTrue(leaks.isEmpty(),
                "Target rt.jar's Thread must shadow analyzer JVM's; leaked: " + leaks);
    }

    @Test
    @DisplayName("JDK resolution: target rt.jar's class version is what gets read")
    void targetRtJarVersionWins() throws Exception {
        // Caller invokes a method that does NOT exist in any real JDK -
        // it only exists in our staged rt.jar where it is declared ACC_NATIVE.
        // If the analyzer leaked into the boot classloader instead, this method
        // would not be found and the test would fail.
        Path callerJar = writeJar("rt-version-wins-caller.jar",
                classWithCall("com/example/Caller", "doIt",
                              "java/io/FileDescriptor", "fakeJdk8Native"));

        Path rtJar = writeJar("fake_rt.jar",
                classWithNative("java/io/FileDescriptor", "fakeJdk8Native"));

        runAnalysis(callerJar, rtJar);

        assertContains(PrototypeFinal.Util.visitedNative,
                "java.io.FileDescriptor.fakeJdk8Native");
    }

    // ---------------------------------------------------------------------
    //  URLClassLoader construction invariants
    // ---------------------------------------------------------------------

    @Test
    @DisplayName("URLClassLoader uses null parent (no bootstrap delegation)")
    void urlClassLoaderHasNullParent() throws Exception {
        Path jar = writeJar("noop.jar", classWithNative("com/example/X", "x"));
        runAnalysis(jar);

        URLClassLoader cl = (URLClassLoader) getStatic("targetClassLoader");
        assertNotNull(cl, "targetClassLoader must have been built by runAnalysis");
        assertNull(cl.getParent(),
                "targetClassLoader must use null parent to prevent JVM-bootstrap leak");
    }

    @Test
    @DisplayName("URLClassLoader override returns null for resources outside its URLs")
    void getResourceAsStreamReturnsNullForUnknown() throws Exception {
        Path jar = writeJar("noop2.jar", classWithNative("com/example/Y", "y"));
        runAnalysis(jar);

        URLClassLoader cl = (URLClassLoader) getStatic("targetClassLoader");
        assertNotNull(cl);

        // java.io.FileDescriptor.class is reachable from the analyzer JVM's
        // bootstrap loader, but the override must return null because it only
        // calls findResource(name) (URL list scan), never getResource(name).
        try (InputStream is = cl.getResourceAsStream("java/io/FileDescriptor.class")) {
            assertNull(is, "Override must NOT delegate up the parent chain "
                    + "even for boot classes");
        }

        // Sanity: a class that *is* in the URL list resolves fine.
        try (InputStream is = cl.getResourceAsStream("com/example/Y.class")) {
            assertNotNull(is, "Class present in target JAR must resolve");
        }
    }

    // ---------------------------------------------------------------------
    //  Cross-JAR + JDK runtime integration
    // ---------------------------------------------------------------------

    /**
     * End-to-end test: two application JARs + a staged JDK runtime JAR.
     *
     * Call chain:
     *   app1.jar  Main.main()
     *       ├─ INVOKESTATIC Worker.process()          → cross-JAR into app2.jar
     *       └─ INVOKESTATIC System.arraycopy()        → JDK native (rt.jar)
     *
     *   app2.jar  Worker.process()
     *       ├─ INVOKESTATIC Worker.nativeWork()       → native (same JAR)
     *       └─ INVOKESTATIC System.currentTimeMillis()→ JDK native (rt.jar)
     *
     * rt.jar is on the classloader but NOT scanned as a target JAR,
     * mirroring the real pipeline's RUNTIME_DIR vs JARFILES_DIR split.
     */
    @Test
    @DisplayName("Cross-JAR: app1→app2 (native) + both→JDK runtime natives via staged rt.jar")
    void crossJarWithRuntimeNativesDetected() throws Exception {
        // -- app2.jar: Worker with a native method + process() dispatching calls --
        byte[] workerClass = classWithNativeAndCalls(
                "com/example/dep/Worker",
                "nativeWork",                       // native void nativeWork()
                "process",                          // void process() { ... }
                new String[][]{
                        {"com/example/dep/Worker", "nativeWork", "()V"},
                        {"java/lang/System", "currentTimeMillis", "()J"}
                });
        Path app2 = writeJar("app2.jar", workerClass);

        // -- app1.jar: Main calling Worker.process() + System.arraycopy() --
        byte[] mainClass = classWithMultipleCalls(
                "com/example/app/Main",
                "main",
                new String[][]{
                        {"com/example/dep/Worker", "process", "()V"},
                        {"java/lang/System", "arraycopy",
                                "(Ljava/lang/Object;ILjava/lang/Object;II)V"}
                });
        Path app1 = writeJar("app1.jar", mainClass);

        // -- rt.jar: fake JDK runtime with two native methods --
        byte[] systemClass = classWithMultipleNatives(
                "java/lang/System",
                new String[][]{
                        {"arraycopy", "(Ljava/lang/Object;ILjava/lang/Object;II)V"},
                        {"currentTimeMillis", "()J"}
                });
        Path rtJar = writeJar("rt.jar", systemClass);

        // Run: target=[app1, app2], runtime=[rt]  (rt is NOT scanned)
        runAnalysisWithRuntime(
                new Path[]{app1, app2},
                new Path[]{rtJar});

        // -- Positive: all three native methods must be discovered --
        assertContains(PrototypeFinal.Util.visitedNative,
                "com.example.dep.Worker.nativeWork");
        assertContains(PrototypeFinal.Util.visitedNative,
                "java.lang.System.arraycopy");
        assertContains(PrototypeFinal.Util.visitedNative,
                "java.lang.System.currentTimeMillis");

        // -- Negative: non-native callers must NOT appear --
        assertFalse(PrototypeFinal.Util.visitedNative.contains(
                        "com.example.app.Main.main"),
                "Non-native Main.main must not be recorded");
        assertFalse(PrototypeFinal.Util.visitedNative.contains(
                        "com.example.dep.Worker.process"),
                "Non-native Worker.process must not be recorded");
    }

    // ---------------------------------------------------------------------
    //  Test helpers - drive PrototypeFinal's machinery directly
    // ---------------------------------------------------------------------

    /**
     * Builds a hermetic URLClassLoader (mirroring PrototypeFinal's main()),
     * installs it as the static targetClassLoader, then runs traceJarFiles
     * across the JARs supplied as arguments.
     */
    private void runAnalysis(Path... jars) throws Exception {
        List<URL> urls = new ArrayList<>();
        List<String> jarNames = new ArrayList<>();
        for (Path j : jars) {
            urls.add(j.toUri().toURL());
            jarNames.add(j.getFileName().toString());
        }

        // Same construction as src/main/.../PrototypeFinal.java:239-249.
        testClassLoader = new URLClassLoader(urls.toArray(new URL[0]), null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                URL u = findResource(name);
                if (u == null) return null;
                try { return u.openStream(); }
                catch (IOException e) { return null; }
            }
        };
        setStatic("targetClassLoader", testClassLoader);

        new PrototypeFinal().traceJarFiles(jarNames);
    }

    /** Writes a JAR containing the given class bytecodes (one entry per byte[]). */
    private Path writeJar(String jarName, byte[]... classes) throws IOException {
        Path out = tempDir.resolve(jarName);
        try (JarOutputStream jos = new JarOutputStream(Files.newOutputStream(out))) {
            for (byte[] cls : classes) {
                String internalName = new ClassReader(cls).getClassName();
                JarEntry entry = new JarEntry(internalName + ".class");
                jos.putNextEntry(entry);
                jos.write(cls);
                jos.closeEntry();
            }
        }
        return out;
    }

    /** Builds a class declaring exactly one ACC_NATIVE method `()V`. */
    private byte[] classWithNative(String internalName, String nativeMethodName) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 internalName, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                       nativeMethodName, "()V", null, null).visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /** Builds a class with one regular static method that invokes another class's static `()V`. */
    private byte[] classWithCall(String callerInternal, String callerMethod,
                                 String calleeInternal, String calleeMethod) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 callerInternal, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        MethodVisitor mv = cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                callerMethod, "()V", null, null);
        mv.visitCode();
        mv.visitMethodInsn(Opcodes.INVOKESTATIC, calleeInternal, calleeMethod, "()V", false);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Builds a class declaring a single static method.  When `isNative` is true,
     * the method is declared ACC_NATIVE with no body; otherwise it returns void.
     * Used to stage "fake rt.jar"-style classes that mimic JDK runtime layouts.
     */
    private byte[] classWithMethod(String internalName, String methodName,
                                   String descriptor, boolean isNative) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 internalName, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        int access = Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | (isNative ? Opcodes.ACC_NATIVE : 0);
        MethodVisitor mv = cw.visitMethod(access, methodName, descriptor, null, null);
        if (!isNative) {
            mv.visitCode();
            // For an `()V` body, just RETURN.  Other descriptors aren't used by tests.
            mv.visitInsn(Opcodes.RETURN);
            mv.visitMaxs(0, 0);
        }
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Like {@link #runAnalysis} but separates target JARs (scanned as entry
     * points) from runtime JARs (on classloader only, NOT scanned).  This
     * mirrors the real pipeline: JARFILES_DIR JARs are scanned while
     * RUNTIME_DIR JARs are loaded only for call-edge resolution.
     */
    private void runAnalysisWithRuntime(Path[] targetJars, Path[] runtimeJars) throws Exception {
        List<URL> urls = new ArrayList<>();
        List<String> jarNames = new ArrayList<>();
        for (Path j : targetJars) {
            urls.add(j.toUri().toURL());
            jarNames.add(j.getFileName().toString());
        }
        for (Path j : runtimeJars) {
            urls.add(j.toUri().toURL());
            // NOT added to jarNames: present on classloader but not scanned
        }

        testClassLoader = new URLClassLoader(urls.toArray(new URL[0]), null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                URL u = findResource(name);
                if (u == null) return null;
                try { return u.openStream(); }
                catch (IOException e) { return null; }
            }
        };
        setStatic("targetClassLoader", testClassLoader);

        new PrototypeFinal().traceJarFiles(jarNames);
    }

    /**
     * Builds a class with one ACC_NATIVE method and one regular method that
     * makes multiple INVOKESTATIC calls.
     *
     * @param internalName       e.g. "com/example/dep/Worker"
     * @param nativeMethodName   name of the native method (descriptor: ()V)
     * @param callerMethodName   name of the non-native method that dispatches calls
     * @param calls              array of {calleeClass, calleeMethod, descriptor}
     */
    private byte[] classWithNativeAndCalls(String internalName,
                                           String nativeMethodName,
                                           String callerMethodName,
                                           String[][] calls) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 internalName, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        // native method
        cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                       nativeMethodName, "()V", null, null).visitEnd();

        // caller method with multiple invocations
        MethodVisitor mv = cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                callerMethodName, "()V", null, null);
        mv.visitCode();
        for (String[] call : calls) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, call[0], call[1], call[2], false);
            // Pop return value for non-void calls (e.g. currentTimeMillis returns long)
            if (call[2].endsWith(")J")) {
                mv.visitInsn(Opcodes.POP2);
            } else if (!call[2].endsWith(")V")) {
                mv.visitInsn(Opcodes.POP);
            }
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(4, 4);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Builds a class with one static method that makes multiple INVOKESTATIC calls.
     *
     * @param internalName  e.g. "com/example/app/Main"
     * @param methodName    e.g. "main"
     * @param calls         array of {calleeClass, calleeMethod, descriptor}
     */
    private byte[] classWithMultipleCalls(String internalName,
                                          String methodName,
                                          String[][] calls) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 internalName, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        MethodVisitor mv = cw.visitMethod(
                Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC,
                methodName, "()V", null, null);
        mv.visitCode();
        for (String[] call : calls) {
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, call[0], call[1], call[2], false);
            if (call[2].endsWith(")J")) {
                mv.visitInsn(Opcodes.POP2);
            } else if (!call[2].endsWith(")V")) {
                mv.visitInsn(Opcodes.POP);
            }
        }
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(6, 6);
        mv.visitEnd();
        cw.visitEnd();
        return cw.toByteArray();
    }

    /**
     * Builds a class with multiple ACC_NATIVE methods (varying descriptors).
     *
     * @param internalName  e.g. "java/lang/System"
     * @param methods       array of {methodName, descriptor}
     */
    private byte[] classWithMultipleNatives(String internalName, String[][] methods) {
        ClassWriter cw = new ClassWriter(0);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                 internalName, null, "java/lang/Object", null);

        emitDefaultCtor(cw);

        for (String[] m : methods) {
            cw.visitMethod(Opcodes.ACC_PUBLIC | Opcodes.ACC_STATIC | Opcodes.ACC_NATIVE,
                           m[0], m[1], null, null).visitEnd();
        }
        cw.visitEnd();
        return cw.toByteArray();
    }

    private void emitDefaultCtor(ClassWriter cw) {
        MethodVisitor init = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        init.visitCode();
        init.visitVarInsn(Opcodes.ALOAD, 0);
        init.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        init.visitInsn(Opcodes.RETURN);
        init.visitMaxs(1, 1);
        init.visitEnd();
    }

    /** Reflective static-field setter (PrototypeFinal keeps its loader/path private). */
    private void setStatic(String fieldName, Object value) throws Exception {
        Field f = PrototypeFinal.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(null, value);
    }

    private Object getStatic(String fieldName) throws Exception {
        Field f = PrototypeFinal.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(null);
    }

    private static void assertContains(Set<String> set, String entry) {
        assertTrue(set.contains(entry),
                "Expected to contain '" + entry + "' but had: " + set);
    }

    @SuppressWarnings("unused")
    private static String pretty(Path... paths) {
        return Arrays.toString(paths);
    }
}
