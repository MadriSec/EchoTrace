package com.echotrace.app.bytecode_new;

import com.echotrace.app.bytecode_new.crossjdk.CrossJdkTestFixtures;
import com.echotrace.app.bytecode_new.crossjdk.DemoNativeApplication;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.io.TempDir;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Set;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end check that {@link PrototypeFinal} can analyze a tiny <em>application</em> JAR
 * (declaring its own {@code native} methods) while resolving callee bytecode from a
 * version-specific <em>JDK runtime</em> JAR staged from {@code rt.jar} or {@code java.base.jmod}.
 *
 * <p><b>Why this matters</b> (see also README "Finding Native Methods"):
 * <ul>
 *   <li><b>Application-level natives</b> — bound to app or dependency {@code .so} files
 *       (JNI name mangling, {@code RegisterNatives}, etc.).</li>
 *   <li><b>JDK natives</b> — implemented in {@code libjvm.so}, {@code libjava.so}, {@code libzip.so},
 *       …; the set and JNI symbol names change across feature releases (new methods, renames,
 *       methods moved from Java to intrinsic, Loom changing {@code Thread}, newer ZIP natives, …).</li>
 * </ul>
 *
 * <p>Running the same app bytecode against different staged JDK runtimes reproduces how CI / seccomp
 * pipelines must pair app JARs with the correct {@code RUNTIME_*} /
 * {@code LIBS_*} / {@code JDK*_LIBS} layout
 * for the container-under-test.
 */
class PrototypeFinalCrossJdkAppAndRuntimeTest {

    @TempDir
    Path tempDir;

    private URLClassLoader testClassLoader;

    static Stream<Arguments> jdkSources() {
        return CrossJdkTestFixtures.allResolvedJdkRuntimeSources();
    }

    @AfterEach
    void tearDown() throws Exception {
        if (testClassLoader != null) {
            try {
                testClassLoader.close();
            } catch (IOException ignored) {
            }
            testClassLoader = null;
        }
        setStatic("targetClassLoader", null);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("jdkSources")
    @DisplayName("App JAR + version-specific JDK runtime on the classloader")
    void appJarWithVersionedRuntime(String label, Path jdkSource) throws Exception {
        Assumptions.assumeTrue(Files.isRegularFile(jdkSource),
                "Skipping " + label + " — not found at " + jdkSource
                        + " (install JDK or run scripts/fetch_test_jdks.sh; set ECHOTRACE_* env).");

        PrototypeFinal.Util.visitedNative.clear();
        PrototypeFinal.Util.visitedMethod.clear();

        Path demoClass = demoClassFile();
        Assumptions.assumeTrue(Files.isRegularFile(demoClass),
                "DemoNativeApplication.class missing at " + demoClass);

        Path appJar = tempDir.resolve("app-demo.jar");
        CrossJdkTestFixtures.writeClassIntoJar(
                appJar,
                demoClass,
                "com/echotrace/app/bytecode_new/crossjdk/DemoNativeApplication.class");

        Path runtimeJar = CrossJdkTestFixtures.stageRuntimeAsJar(tempDir, jdkSource);

        String prefix = tempDir.toString();
        if (!prefix.endsWith("/")) {
            prefix += "/";
        }
        setStatic("pathPrefix", prefix);
        setStatic("targetClassLoader", null);

        URL[] urls = new URL[]{appJar.toUri().toURL(), runtimeJar.toUri().toURL()};
        testClassLoader = new URLClassLoader(urls, null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                URL u = findResource(name);
                if (u == null) {
                    return null;
                }
                try {
                    return u.openStream();
                } catch (IOException e) {
                    return null;
                }
            }
        };
        setStatic("targetClassLoader", testClassLoader);

        new PrototypeFinal().traceJarFiles(Collections.singletonList("app-demo.jar"));

        Set<String> natives = PrototypeFinal.Util.visitedNative;
        assertTrue(natives.contains("com.echotrace.app.bytecode_new.crossjdk.DemoNativeApplication.applicationPing"),
                label + " should list app native; got " + natives);
        assertTrue(natives.contains("java.lang.Object.hashCode"),
                label + " should follow invoke into JDK Object.hashCode; got " + natives);
    }

    private static Path demoClassFile() throws Exception {
        Path root = Paths.get(DemoNativeApplication.class.getProtectionDomain().getCodeSource().getLocation().toURI());
        return root.resolve("com/echotrace/app/bytecode_new/crossjdk/DemoNativeApplication.class");
    }

    private void setStatic(String fieldName, Object value) throws Exception {
        Field f = PrototypeFinal.class.getDeclaredField(fieldName);
        f.setAccessible(true);
        f.set(null, value);
    }
}
