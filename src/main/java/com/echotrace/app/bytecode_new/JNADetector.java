package com.echotrace.app.bytecode_new;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Unified native-binding detector that runs JNA dynamic, JNA interface,
 * JNA direct-map, Java FFM/Panama, and jnr-ffi detectors, then merges their
 * outputs into a single keep-all report. After that, it runs PrototypeFinal
 * and stores its output under outDir/prototype_final.
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
 *     -Dexec.args="<target-jars-dir> [outDir] [runtime-jars-dir]"
 *
 * Outputs (in outDir):
 *   - jna_hits.txt
 *   - skipped_methods.txt
 *   - jna_dyn_hits.txt
 *   - jna_iface_hits.txt
 *   - jna_directmap_hits.txt
 *   - ffi_hits.txt
 *   - jnr_ffi_hits.txt
 *   - ffi_all_hits.txt
 *   - native_methods.txt
 */
public class JNADetector {

    private static final String DYN = "dyn";
    private static final String IFACE = "iface";
    private static final String DIRECTMAP = "directmap";
    private static final String FFI = "ffi";
    private static final String JNR_FFI = "jnr-ffi";

    private static final DateTimeFormatter TS_FMT = DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss");

    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("Usage: JNADetector <target-jars-dir> [outDir] [runtime-jars-dir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir;
        if (args.length >= 2) {
            outDir = args[1];
        } else {
            String dirName = new File(targetDir).getName();
            if (dirName.startsWith("JARFILES_")) {
                outDir = "outputs_" + dirName.substring("JARFILES_".length());
            } else {
                outDir = "outputs_" + dirName;
            }
        }

        String runtimeDir = null;
        if (args.length >= 3) {
            runtimeDir = args[2];
        } else {
            runtimeDir = detectRuntimeDir(targetDir);
        }
        if (runtimeDir == null || runtimeDir.isEmpty()) {
            throw new IllegalArgumentException(
                    "PrototypeFinal requires a runtime JAR directory. Pass: JNADetector <target-jars-dir> [outDir] <runtime-jars-dir>");
        }

        Path outPath = Paths.get(outDir);
        Files.createDirectories(outPath);

        String runStamp = LocalDateTime.now().format(TS_FMT);
        Path workRoot = outPath.resolve("jna_detector_work_" + runStamp);
        Files.createDirectories(workRoot);

        Path dynOutDir = workRoot.resolve("dyn");
        Path ifaceOutDir = workRoot.resolve("iface");
        Path directOutDir = workRoot.resolve("directmap");
        Path ffiOutDir = workRoot.resolve("ffi");
        Path jnrOutDir = workRoot.resolve("jnr-ffi");
        Files.createDirectories(dynOutDir);
        Files.createDirectories(ifaceOutDir);
        Files.createDirectories(directOutDir);
        Files.createDirectories(ffiOutDir);
        Files.createDirectories(jnrOutDir);

        System.out.println("[JNADetector] target=" + targetDir);
        System.out.println("[JNADetector] out   =" + outPath.toAbsolutePath());
        System.out.println("[JNADetector] runtime=" + Paths.get(runtimeDir).toAbsolutePath());
        System.out.println("[JNADetector] work  =" + workRoot.toAbsolutePath());

        writeAnalyzedJarsManifest(targetDir, runtimeDir, outPath.resolve("analyzed_jars.txt"));
        copyIfExists(outPath.resolve("analyzed_jars.txt"), workRoot.resolve("analyzed_jars.txt"));

        runDynamic(targetDir, dynOutDir.toString());
        runInterface(targetDir, ifaceOutDir.toString());
        runDirectMap(targetDir, directOutDir.toString());
        runFfi(targetDir, ffiOutDir.toString());
        runJnrFfi(targetDir, jnrOutDir.toString());

        Path dynHits = dynOutDir.resolve("jna_dyn_hits.txt");
        Path ifaceHits = ifaceOutDir.resolve("jna_iface_hits.txt");
        Path directHits = directOutDir.resolve("jna_directmap_hits.txt");
        Path ffiHits = ffiOutDir.resolve("ffi_hits.txt");
        Path jnrHits = jnrOutDir.resolve("jnr_ffi_hits.txt");

        Path dynSkipped = dynOutDir.resolve("skipped_methods.txt");
        Path ifaceSkipped = ifaceOutDir.resolve("skipped_methods.txt");
        Path directSkipped = directOutDir.resolve("skipped_methods.txt");
        Path ffiSkipped = ffiOutDir.resolve("skipped_methods.txt");
        Path jnrSkipped = jnrOutDir.resolve("skipped_methods.txt");

        Path combinedHits = outPath.resolve("jna_hits.txt");
        Path combinedSkipped = outPath.resolve("skipped_methods.txt");
        Path combinedFfiHits = outPath.resolve("ffi_all_hits.txt");
        Path combinedFfiSkipped = outPath.resolve("ffi_all_skipped_methods.txt");

        mergeHits(combinedHits, dynHits, ifaceHits, directHits, ffiHits, jnrHits);
        mergeSkipped(combinedSkipped, dynSkipped, ifaceSkipped, directSkipped, ffiSkipped, jnrSkipped);
        mergeFfiFamilyHits(combinedFfiHits, ffiHits, jnrHits);
        mergeFfiFamilySkipped(combinedFfiSkipped, ffiSkipped, jnrSkipped);

        // Keep detector-native output files in the requested outDir as well.
        copyIfExists(dynHits, outPath.resolve("jna_dyn_hits.txt"));
        copyIfExists(ifaceHits, outPath.resolve("jna_iface_hits.txt"));
        copyIfExists(directHits, outPath.resolve("jna_directmap_hits.txt"));
        copyIfExists(ffiHits, outPath.resolve("ffi_hits.txt"));
        copyIfExists(jnrHits, outPath.resolve("jnr_ffi_hits.txt"));

        System.out.println("[JNADetector] wrote " + combinedHits.toAbsolutePath());
        System.out.println("[JNADetector] wrote " + combinedSkipped.toAbsolutePath());
        System.out.println("[JNADetector] wrote " + combinedFfiHits.toAbsolutePath());
        System.out.println("[JNADetector] wrote " + combinedFfiSkipped.toAbsolutePath());

        runPrototypeFinal(targetDir, runtimeDir, outPath);

        System.out.println("[JNADetector] done");
    }

    private static void writeAnalyzedJarsManifest(String targetDir, String runtimeDir, Path outFile) throws IOException {
        List<String> targetJars = listArchiveFiles(Paths.get(targetDir));
        List<String> runtimeJars = listArchiveFiles(Paths.get(runtimeDir));

        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== JNADetector Analyzed Archives ===\n");
            w.write("targetDir=" + Paths.get(targetDir).toAbsolutePath() + "\n");
            w.write("runtimeDir=" + Paths.get(runtimeDir).toAbsolutePath() + "\n");
            w.write("targetArchives=" + targetJars.size() + "\n");
            w.write("runtimeArchives=" + runtimeJars.size() + "\n\n");

            w.write("[target]\n");
            for (String jar : targetJars) {
                w.write(jar);
                w.write("\n");
            }

            w.write("\n[runtime]\n");
            for (String jar : runtimeJars) {
                w.write(jar);
                w.write("\n");
            }
        }

        System.out.println("[JNADetector] wrote " + outFile.toAbsolutePath()
                + " (target=" + targetJars.size() + ", runtime=" + runtimeJars.size() + ")");
    }

    private static List<String> listArchiveFiles(Path dir) throws IOException {
        List<String> archives = new ArrayList<>();
        if (dir == null || !Files.isDirectory(dir)) {
            return archives;
        }

        try (java.util.stream.Stream<Path> stream = Files.walk(dir)) {
            stream
                    .filter(Files::isRegularFile)
                    .filter(p -> {
                        String name = p.getFileName().toString().toLowerCase();
                        return name.endsWith(".jar") || name.endsWith(".jmod");
                    })
                    .forEach(p -> archives.add(p.toAbsolutePath().toString()));
        }
        Collections.sort(archives);
        return archives;
    }

    private static String detectRuntimeDir(String targetDir) {
        String envRuntime = System.getenv("PROTOTYPE_RUNTIME_DIR");
        if (envRuntime != null && !envRuntime.isEmpty()) {
            return envRuntime;
        }

        File target = new File(targetDir).getAbsoluteFile();
        String name = target.getName();
        if (!name.startsWith("JARFILES_")) {
            return null;
        }

        File parent = target.getParentFile();
        if (parent == null) {
            return null;
        }

        String suffix = name.substring("JARFILES_".length());
        File runtime = new File(parent, "RUNTIME_" + suffix);
        if (runtime.isDirectory()) {
            return runtime.getAbsolutePath();
        }

        File jdkRuntime = new File(parent, "JDK_RUNTIME_" + suffix);
        if (jdkRuntime.isDirectory()) {
            return jdkRuntime.getAbsolutePath();
        }

        return null;
    }

    private static void runPrototypeFinal(String targetDir, String runtimeDir, Path outDir) throws Exception {
        Files.createDirectories(outDir);
        System.out.println("[JNADetector] phase=prototype-final");
        System.out.println("[JNADetector] prototype-final out=" + outDir.toAbsolutePath());

        String previousOutDir = System.getProperty("prototype.output.dir");
        System.setProperty("prototype.output.dir", outDir.toString());
        try {
            PrototypeFinal.main(new String[]{targetDir, "--1", "--runtime", runtimeDir});
        } finally {
            if (previousOutDir == null) {
                System.clearProperty("prototype.output.dir");
            } else {
                System.setProperty("prototype.output.dir", previousOutDir);
            }
        }
    }

    private static void runDynamic(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + DYN);
        JnaDynDetector.main(new String[]{targetDir, outDir});
    }

    private static void runInterface(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + IFACE);
        JnaIfaceDetector.main(new String[]{targetDir, outDir});
    }

    private static void runDirectMap(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + DIRECTMAP);
        JnaDirectMapDetector.main(new String[]{targetDir, outDir});
    }

    private static void runFfi(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + FFI);
        FfiDetector.main(new String[]{targetDir, outDir});
    }

    private static void runJnrFfi(String targetDir, String outDir) throws Exception {
        System.out.println("[JNADetector] phase=" + JNR_FFI);
        JnrFfiDetector.main(new String[]{targetDir, outDir});
    }

    private static void mergeHits(Path outFile, Path dynFile, Path ifaceFile, Path directFile, Path ffiFile, Path jnrFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined Native Binding Hits ===\n");
            w.write("Format: detector | payload\n\n");

            appendHitsFile(w, DYN, dynFile);
            appendHitsFile(w, IFACE, ifaceFile);
            appendHitsFile(w, DIRECTMAP, directFile);
            appendHitsFile(w, FFI, ffiFile);
            appendHitsFile(w, JNR_FFI, jnrFile);
        }
    }

    private static void appendHitsFile(BufferedWriter w, String detector, Path file) throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (trimmed.startsWith("===") || trimmed.startsWith("Format:")) {
                    continue;
                }
                w.write(detector);
                w.write(" | ");
                w.write(line);
                w.write('\n');
            }
        }
    }

    private static void mergeSkipped(Path outFile, Path dynFile, Path ifaceFile, Path directFile, Path ffiFile, Path jnrFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined Skipped Methods ===\n");
            w.write("Format: detector | payload\n\n");

            appendSkippedFile(w, DYN, dynFile);
            appendSkippedFile(w, IFACE, ifaceFile);
            appendSkippedFile(w, DIRECTMAP, directFile);
            appendSkippedFile(w, FFI, ffiFile);
            appendSkippedFile(w, JNR_FFI, jnrFile);
        }
    }

    private static void mergeFfiFamilyHits(Path outFile, Path ffiFile, Path jnrFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined FFI Native Binding Hits ===\n");
            w.write("Format: detector | payload\n\n");

            appendHitsFile(w, FFI, ffiFile);
            appendHitsFile(w, JNR_FFI, jnrFile);
        }
    }

    private static void mergeFfiFamilySkipped(Path outFile, Path ffiFile, Path jnrFile) throws IOException {
        try (BufferedWriter w = Files.newBufferedWriter(outFile, StandardCharsets.UTF_8)) {
            w.write("=== Combined FFI Skipped Methods ===\n");
            w.write("Format: detector | payload\n\n");

            appendSkippedFile(w, FFI, ffiFile);
            appendSkippedFile(w, JNR_FFI, jnrFile);
        }
    }

    private static void appendSkippedFile(BufferedWriter w, String detector, Path file) throws IOException {
        if (!Files.exists(file)) {
            return;
        }
        try (BufferedReader r = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = r.readLine()) != null) {
                String trimmed = line.trim();
                if (trimmed.isEmpty()) {
                    continue;
                }
                if (trimmed.startsWith("===") || trimmed.startsWith("Format:")) {
                    continue;
                }
                w.write(detector);
                w.write(" | ");
                w.write(line);
                w.write('\n');
            }
        }
    }

    private static void copyIfExists(Path src, Path dst) throws IOException {
        if (!Files.exists(src)) {
            return;
        }
        Files.copy(src, dst, java.nio.file.StandardCopyOption.REPLACE_EXISTING);
    }
}
