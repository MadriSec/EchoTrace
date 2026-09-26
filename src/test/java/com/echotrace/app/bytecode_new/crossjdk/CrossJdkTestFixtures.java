package com.echotrace.app.bytecode_new.crossjdk;

import org.junit.jupiter.params.provider.Arguments;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Objects;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;
import java.util.stream.Stream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Shared JDK layout paths and staging helpers for cross-JDK PrototypeFinal tests.
 *
 * <p>Paths resolve in order: JVM system property ({@code echotrace.jdk*.}), environment
 * variable ({@code ECHOTRACE_*}), conventional Linux locations, then optional trees under
 * {@code <project>/JDKs/} (Temurin installs or tarballs extracted by the team).
 *
 * <p>Missing JDK artifacts are not errors here: tests use {@link org.junit.jupiter.api.Assumptions}
 * to skip. Use {@code scripts/fetch_test_jdks.sh} for jmods not installed on the host.
 */
public final class CrossJdkTestFixtures {

    private static final Path USER_DIR = Paths.get(System.getProperty("user.dir", ".")).toAbsolutePath().normalize();

    private CrossJdkTestFixtures() {}

    public static Path projectRoot() {
        return USER_DIR;
    }

    private static String prop(String key) {
        String v = System.getProperty(key);
        return v == null || v.isBlank() ? null : v;
    }

    private static String env(String key) {
        String v = System.getenv(key);
        return v == null || v.isBlank() ? null : v;
    }

    private static Path firstExisting(Path... candidates) {
        for (Path p : candidates) {
            if (p != null && Files.isRegularFile(p)) {
                return p;
            }
        }
        return null;
    }

    /** JDK 8 rt.jar or equivalent flat runtime JAR. */
    public static Path resolveJdk8RtJar() {
        Path p = firstExisting(
                pathOrNull(prop("echotrace.jdk8.rt.jar")),
                pathOrNull(env("ECHOTRACE_JDK8_RT_JAR")),
                Paths.get("/usr/lib/jvm/java-8-openjdk-amd64/jre/lib/rt.jar"),
                Paths.get("/usr/lib/jvm/java-1.8.0-openjdk/jre/lib/rt.jar")
        );
        return p;
    }

    /** JDK 9+ {@code java.base.jmod} (any JDK version). */
    public static Path resolveJmod(String envKey, String propKey, Path... fallbacks) {
        List<Path> list = new ArrayList<>();
        Path a = pathOrNull(prop(propKey));
        if (a != null) {
            list.add(a);
        }
        Path b = pathOrNull(env(envKey));
        if (b != null) {
            list.add(b);
        }
        for (Path f : fallbacks) {
            if (f != null) {
                list.add(f);
            }
        }
        return firstExisting(list.toArray(Path[]::new));
    }

    private static Path pathOrNull(String s) {
        return s == null ? null : Paths.get(s);
    }

    public static Path resolveJdk9JavaBaseJmod() {
        return resolveJmod(
                "ECHOTRACE_JDK9_JAVA_BASE_JMOD",
                "echotrace.jdk9.java.base.jmod",
                Paths.get("/tmp/jdks_for_test/jdk9_java.base.jmod"));
    }

    public static Path resolveJdk11JavaBaseJmod() {
        return resolveJmod(
                "ECHOTRACE_JDK11_JAVA_BASE_JMOD",
                "echotrace.jdk11.java.base.jmod",
                USER_DIR.resolve("JDKs").resolve("jdk-11.0.31+11").resolve("jmods").resolve("java.base.jmod"),
                Paths.get("/usr/lib/jvm/java-11-openjdk-amd64/jmods/java.base.jmod"),
                Paths.get("/usr/lib/jvm/java-11-openjdk/jmods/java.base.jmod"));
    }

    public static Path resolveJdk15JavaBaseJmod() {
        return resolveJmod(
                "ECHOTRACE_JDK15_JAVA_BASE_JMOD",
                "echotrace.jdk15.java.base.jmod",
                Paths.get("/tmp/jdks_for_test/jdk15_java.base.jmod"));
    }

    public static Path resolveJdk21JavaBaseJmod() {
        return resolveJmod(
                "ECHOTRACE_JDK21_JAVA_BASE_JMOD",
                "echotrace.jdk21.java.base.jmod",
                Paths.get("/tmp/jdks_for_test/jdk21_java.base.jmod"));
    }

    public static Path resolveJdk25JavaBaseJmod() {
        return resolveJmod(
                "ECHOTRACE_JDK25_JAVA_BASE_JMOD",
                "echotrace.jdk25.java.base.jmod",
                USER_DIR.resolve("JDKs").resolve("jdk-25.0.3+9").resolve("jmods").resolve("java.base.jmod"));
    }

    /**
     * All JDK fixtures we can locate on this machine, for parameterized tests.
     * Order is ascending by rough era (8 → 9 → 11 → 15 → 21 → 25).
     */
    public static Stream<Arguments> allResolvedJdkRuntimeSources() {
        List<Arguments> args = new ArrayList<>();
        Path p8 = resolveJdk8RtJar();
        if (p8 != null) {
            args.add(Arguments.of("JDK 8  (rt.jar)", p8));
        }
        Path p9 = resolveJdk9JavaBaseJmod();
        if (p9 != null) {
            args.add(Arguments.of("JDK 9  (java.base.jmod)", p9));
        }
        Path p11 = resolveJdk11JavaBaseJmod();
        if (p11 != null) {
            args.add(Arguments.of("JDK 11 (java.base.jmod)", p11));
        }
        Path p15 = resolveJdk15JavaBaseJmod();
        if (p15 != null) {
            args.add(Arguments.of("JDK 15 (java.base.jmod)", p15));
        }
        Path p21 = resolveJdk21JavaBaseJmod();
        if (p21 != null) {
            args.add(Arguments.of("JDK 21 (java.base.jmod)", p21));
        }
        Path p25 = resolveJdk25JavaBaseJmod();
        if (p25 != null) {
            args.add(Arguments.of("JDK 25 (java.base.jmod)", p25));
        }
        return args.stream();
    }

    /**
     * Repacks {@code source} into a flat JAR under {@code tempDir}. For JDK 8 {@code rt.jar}
     * this copies as-is; for JDK 9+ {@code .jmod} strips the {@code classes/} prefix.
     */
    public static Path stageRuntimeAsJar(Path tempDir, Path source) throws IOException {
        String fileName = source.getFileName().toString();
        if (fileName.endsWith(".jar")) {
            Path target = tempDir.resolve(fileName);
            Files.copy(source, target);
            return target;
        }
        Path target = tempDir.resolve(fileName + ".jar");
        try (ZipFile zf = new ZipFile(source.toFile());
             JarOutputStream jout = new JarOutputStream(Files.newOutputStream(target))) {
            byte[] buf = new byte[8192];
            Enumeration<? extends ZipEntry> entries = zf.entries();
            while (entries.hasMoreElements()) {
                ZipEntry e = entries.nextElement();
                if (e.isDirectory()) {
                    continue;
                }
                String name = e.getName();
                if (!name.startsWith("classes/")) {
                    continue;
                }
                String stripped = name.substring("classes/".length());
                if (!stripped.endsWith(".class")) {
                    continue;
                }
                jout.putNextEntry(new JarEntry(stripped));
                try (InputStream in = zf.getInputStream(e)) {
                    int n;
                    while ((n = in.read(buf)) > 0) {
                        jout.write(buf, 0, n);
                    }
                }
                jout.closeEntry();
            }
        }
        return target;
    }

    /**
     * Pack a single .class file into {@code outJar}, preserving the package path under {@code entryPrefix}
     * (e.g. {@code com/foo/Bar.class}).
     */
    public static void writeClassIntoJar(Path outJar, Path classFile, String entryName) throws IOException {
        Objects.requireNonNull(entryName, "entryName");
        Files.createDirectories(outJar.getParent());
        try (JarOutputStream jout = new JarOutputStream(Files.newOutputStream(outJar))) {
            jout.putNextEntry(new JarEntry(entryName));
            Files.copy(classFile, jout);
            jout.closeEntry();
        }
    }
}
