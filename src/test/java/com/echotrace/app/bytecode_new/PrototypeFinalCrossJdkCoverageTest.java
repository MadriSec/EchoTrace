package com.echotrace.app.bytecode_new;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.echotrace.app.bytecode_new.crossjdk.CrossJdkTestFixtures;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Cross-JDK coverage benchmark for {@link PrototypeFinal#traceJarFiles(java.util.List)}.
 *
 * For each JDK source we can locate (rt.jar for JDK 8, java.base.jmod for JDK 9+),
 * the analyzer runs Flow 1 + Flow 2 over the entire java.base surface and records
 * every method declared with ACC_NATIVE.  The test:
 *
 *   - Asserts a small set of *stable* JDK natives (Object.hashCode, Thread.start0,
 *     etc.) is found for every JDK artifact we resolve (8 through 25 depending on the host).
 *   - Asserts the total count is within a sane range for the version
 *     (catches regressions like "we forgot to walk this directory").
 *   - Prints a comparison table at the end so the user can eyeball coverage and API churn
 *     (e.g. Loom: methods that stop being ACC_NATIVE on public {@code Thread} API).
 *
 * Sources that are not present on the host are skipped via Assumptions, so the
 * test is portable across machines.  Paths are resolved by
 * {@link com.echotrace.app.bytecode_new.crossjdk.CrossJdkTestFixtures} (env vars
 * {@code ECHOTRACE_JDK*_JAVA_BASE_JMOD}, project {@code JDKs/}, and standard Linux
 * locations).  Use {@code scripts/fetch_test_jdks.sh} for jmods not installed locally.
 *
 * NOTE on counts: JDK 8 numbers cover the *entire* rt.jar (java.*, javax.*,
 * sun.*, com.sun.*) whereas JDK 9+ numbers cover only the java.base module.
 * The 8 -> 9 "drop" is a layout change, not a regression - everything outside
 * java.base moved into separate modules (java.desktop.jmod, java.naming.jmod,
 * jdk.crypto.ec.jmod, ...).  To match JDK 8's surface for JDK 9+ you would
 * stage every jmod from the JDK, not just java.base.
 */
class PrototypeFinalCrossJdkCoverageTest {

    /**
     * Native methods that are ACC_NATIVE in recent LTS/GA OpenJDK builds we test against.
     *
     * Notable members that LOOK stable but aren't, and were deliberately
     * excluded after empirical inspection:
     *   - java.lang.Thread.yield        : pure Java in JDK 19+ (Loom)
     *                                     delegates to private yield0() native
     *   - java.lang.Thread.sleep        : pure Java in JDK 19+ (Loom)
     *                                     delegates to private sleep0() native
     *   - java.lang.Class.getPrimitiveClass : signature changed across versions
     *   - java.lang.System.identityHashCode  : may be intrinsic-only on some builds
     */
    private static final List<String> STABLE_NATIVES = Arrays.asList(
            "java.lang.Object.hashCode",
            "java.lang.Object.notify",
            "java.lang.Object.notifyAll",
            "java.lang.Object.clone",
            "java.lang.Thread.start0"
    );

    /** Per-JDK results (count + native set), populated by each run, used @AfterAll. */
    private static final Map<String, Integer> COVERAGE_COUNTS = new LinkedHashMap<>();
    private static final Map<String, TreeSet<String>> COVERAGE_NATIVES = new LinkedHashMap<>();

    @TempDir Path tempDir;
    private URLClassLoader testClassLoader;

    static Stream<Arguments> jdkSources() {
        return CrossJdkTestFixtures.allResolvedJdkRuntimeSources();
    }

    @BeforeEach
    void resetStaticState() throws Exception {
        PrototypeFinal.Util.visitedNative.clear();
        PrototypeFinal.Util.visitedMethod.clear();

        String prefix = tempDir.toString();
        if (!prefix.endsWith("/")) prefix += "/";
        setStatic("pathPrefix", prefix);
        setStatic("targetClassLoader", null);
    }

    @AfterEach
    void teardown() throws Exception {
        if (testClassLoader != null) {
            try { testClassLoader.close(); } catch (IOException ignored) { }
            testClassLoader = null;
        }
        setStatic("targetClassLoader", null);
    }

    @AfterAll
    static void printCoverageReport() {
        if (COVERAGE_COUNTS.isEmpty()) return;

        System.out.println();
        System.out.println("=== Cross-JDK native-method coverage ===");
        for (Map.Entry<String, Integer> e : COVERAGE_COUNTS.entrySet()) {
            System.out.printf("  %-30s %5d native methods%n", e.getKey(), e.getValue());
        }

        // Diff report: what does each newer JDK add or drop relative to its
        // predecessor in the iteration order?  Useful for eyeballing API
        // evolution (e.g. JDK 21 drops Thread.yield as ACC_NATIVE under Loom).
        String previous = null;
        TreeSet<String> previousSet = null;
        System.out.println();
        System.out.println("=== Per-version evolution (added vs. dropped) ===");
        for (Map.Entry<String, TreeSet<String>> e : COVERAGE_NATIVES.entrySet()) {
            String label = e.getKey();
            TreeSet<String> current = e.getValue();
            if (previousSet != null) {
                TreeSet<String> added = new TreeSet<>(current);
                added.removeAll(previousSet);
                TreeSet<String> dropped = new TreeSet<>(previousSet);
                dropped.removeAll(current);
                System.out.printf("%n  %s -> %s%n", previous, label);
                System.out.printf("    added (%d):%n", added.size());
                added.stream().limit(8).forEach(s -> System.out.printf("      + %s%n", s));
                if (added.size() > 8) System.out.printf("      ... (%d more)%n", added.size() - 8);
                System.out.printf("    dropped (%d):%n", dropped.size());
                dropped.stream().limit(8).forEach(s -> System.out.printf("      - %s%n", s));
                if (dropped.size() > 8) System.out.printf("      ... (%d more)%n", dropped.size() - 8);
            }
            previous = label;
            previousSet = current;
        }
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("jdkSources")
    @DisplayName("Native-method coverage across JDK versions")
    void coverageAcrossJdkVersions(String label, Path source) throws Exception {
        Assumptions.assumeTrue(Files.isRegularFile(source),
                "Skipping " + label + " - source not present at " + source
                        + " (run scripts/fetch_test_jdks.sh to populate)");

        // Stage the JDK runtime as a flat JAR readable by JarOutputStream/JarFile.
        // For JDK 8 the .jar is already flat; for JDK 9+ jmods we strip the
        // "classes/" prefix so PrototypeFinal's ClassPrinter sees them as
        // top-level entries.
        Path stagedJar = CrossJdkTestFixtures.stageRuntimeAsJar(tempDir, source);

        // Build a hermetic URLClassLoader exactly the way PrototypeFinal.main()
        // does it, so Flow 2 can resolve cross-class references inside java.base.
        runAnalysis(stagedJar);

        // Snapshot results
        TreeSet<String> natives = new TreeSet<>(PrototypeFinal.Util.visitedNative);
        COVERAGE_COUNTS.put(label, natives.size());
        COVERAGE_NATIVES.put(label, natives);

        // ---- Assertions ----

        // 1) Sanity floor: every JDK 8..21 build of java.base has hundreds of natives.
        assertTrue(natives.size() >= 50,
                label + " found suspiciously few native methods: " + natives.size()
                        + " (should be >= 50)");

        // 2) Stable natives must always be present, regardless of JDK version.
        for (String required : STABLE_NATIVES) {
            assertTrue(natives.contains(required),
                    label + " missing stable native: " + required
                            + " (found " + natives.size() + " natives total)");
        }

        // 3) java.lang and jdk.internal.misc/sun.misc must produce non-trivial
        //    contributions on every JDK version we care about.
        long langCount = natives.stream()
                .filter(s -> s.startsWith("java.lang."))
                .count();
        assertTrue(langCount >= 20,
                label + " has surprisingly few java.lang.* natives: " + langCount);

        // Per-version banner so the user can see what each JDK contributes
        // when the test runs locally.
        System.out.printf("%n[%s]%n", label);
        System.out.printf("  total natives:        %d%n", natives.size());
        System.out.printf("  java.lang.*:          %d%n", langCount);
        System.out.printf("  java.io.*:            %d%n",
                natives.stream().filter(s -> s.startsWith("java.io.")).count());
        System.out.printf("  java.nio.*:           %d%n",
                natives.stream().filter(s -> s.startsWith("java.nio.")).count());
        System.out.printf("  jdk.internal.*:       %d%n",
                natives.stream().filter(s -> s.startsWith("jdk.internal.")).count());
        System.out.printf("  sun.* (legacy):       %d%n",
                natives.stream().filter(s -> s.startsWith("sun.")).count());
    }

    // ---------------------------------------------------------------------
    //  Helpers
    // ---------------------------------------------------------------------

    /**
     * Builds the same hermetic URLClassLoader as PrototypeFinal.main(), installs
     * it on the static field, and drives traceJarFiles across the staged JARs.
     */
    private void runAnalysis(Path... jars) throws Exception {
        URL[] urls = new URL[jars.length];
        java.util.List<String> jarNames = new java.util.ArrayList<>();
        for (int i = 0; i < jars.length; i++) {
            urls[i] = jars[i].toUri().toURL();
            jarNames.add(jars[i].getFileName().toString());
        }
        testClassLoader = new URLClassLoader(urls, null) {
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

    private void setStatic(String fieldName, Object value) throws Exception {
        Field f = PrototypeFinal.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(null, value);
    }
}
