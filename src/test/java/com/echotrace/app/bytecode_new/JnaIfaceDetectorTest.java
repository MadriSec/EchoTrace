package com.echotrace.app.bytecode_new;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for JnaIfaceDetector.
 *
 * Runs the detector on pre-built fixture JARs and asserts that
 * all expected JNA interface call patterns are detected.
 *
 * Fixture JARs are in src/test/fixtures/jna_test/jars/ and must be
 * rebuilt via build_test_jars.sh if fixture sources change.
 */
class JnaIfaceDetectorTest {

    private static final String FIXTURES_DIR = "src/test/fixtures/jna_test/jars";
    private static List<ParsedHit> hits;
    private static Path outDir;

    @BeforeAll
    static void runDetector() throws Exception {
        // Resolve fixture dir relative to project root
        File fixturesDir = new File(FIXTURES_DIR);
        assertTrue(fixturesDir.exists(),
                "Fixture JARs not found at " + fixturesDir.getAbsolutePath()
                        + ". Run: cd src/test/fixtures/jna_test && bash build_test_jars.sh");

        // Create temp output dir
        outDir = Files.createTempDirectory("jna_iface_test_");

        // Run the detector
        JnaIfaceDetector.main(new String[]{
                fixturesDir.getAbsolutePath(),
                outDir.toString()
        });

        // Parse the hits file
        File hitsFile = new File(outDir.toFile(), "jna_iface_hits.txt");
        assertTrue(hitsFile.exists(), "Hits file not created: " + hitsFile.getAbsolutePath());

        hits = parseHitsFile(hitsFile);
        assertFalse(hits.isEmpty(), "No hits detected — detector found nothing");
    }

    // ---- Basic INSTANCE pattern (existing CLib fixture) ----

    @Test
    void testBasicInstance_strlen() {
        List<ParsedHit> matching = findHits("MyApp", "strlen");
        assertFalse(matching.isEmpty(), "Expected hit for MyApp calling strlen via CLib.INSTANCE");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib);
        assertEquals("strlen", h.symbol);
        assertTrue(h.iface.contains("CLib"), "Interface should be CLib, got: " + h.iface);
        assertEquals("myapp.jar", h.callerJar);
        assertEquals("mylib.jar", h.calleeJar);
    }

    @Test
    void testBasicInstance_getpid() {
        List<ParsedHit> matching = findHits("MyApp", "getpid");
        assertFalse(matching.isEmpty(), "Expected hit for MyApp calling getpid via CLib.INSTANCE");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib);
        assertEquals("getpid", h.symbol);
    }

    @Test
    void testBasicInstance_getuid() {
        List<ParsedHit> matching = findHits("MyApp", "getuid");
        assertFalse(matching.isEmpty(), "Expected hit for MyApp calling getuid via CLib.INSTANCE");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib);
        assertEquals("getuid", h.symbol);
    }

    // ---- StdCallLibrary inheritance (MyKernel32 -> StdCallLibrary -> Library) ----
    // These are now excluded by platform filter (kernel32 = Windows)

    @Test
    void testStdCallInheritance_Beep() {
        List<ParsedHit> matching = findHits("WinApp", "Beep");
        assertTrue(matching.isEmpty(), "kernel32 hits should be filtered out by platform exclusion");
    }

    @Test
    void testStdCallInheritance_GetCurrentProcessId() {
        List<ParsedHit> matching = findHits("WinApp", "GetCurrentProcessId");
        assertTrue(matching.isEmpty(), "kernel32 hits should be filtered out by platform exclusion");
    }

    // ---- Edge case #3: Different field name (INSTANCE2) ----

    @Test
    void testDifferentFieldName_INSTANCE2_getpid() {
        List<ParsedHit> matching = findHits("EdgeCases", "getpidViaInstance2", "getpid");
        assertFalse(matching.isEmpty(),
                "Expected hit for EdgeCases.getpidViaInstance2 — INSTANCE2 field should resolve lib=c");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib, "INSTANCE2 should resolve to lib=c via field taint tracking");
        assertEquals("getpid", h.symbol);
        assertTrue(h.iface.contains("CLib"), "Interface should still be CLib");
    }

    @Test
    void testDifferentFieldName_INSTANCE2_strlen() {
        List<ParsedHit> matching = findHits("EdgeCases", "strlenViaInstance2", "strlen");
        assertFalse(matching.isEmpty(),
                "Expected hit for EdgeCases.strlenViaInstance2 — INSTANCE2 field should resolve lib=c");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib);
        assertEquals("strlen", h.symbol);
    }

    // ---- Edge case #4: Different interface (PosixLib) + Edge case #7: null lib ----

    @Test
    void testDifferentInterface_PosixLib_nullLib() {
        List<ParsedHit> matching = findHits("EdgeCases", "getpidViaPosixLib", "getpid");
        assertFalse(matching.isEmpty(),
                "Expected hit for EdgeCases.getpidViaPosixLib — PosixLib interface with null lib");

        ParsedHit h = matching.get(0);
        assertTrue(h.lib.contains("null") || h.lib.contains("default"),
                "PosixLib uses Native.load(null, ...), expected lib containing 'null' or 'default', got: " + h.lib);
        assertEquals("getpid", h.symbol);
        assertTrue(h.iface.contains("PosixLib"), "Interface should be PosixLib, got: " + h.iface);
    }

    // ---- Edge case #5: Local variable instead of static field ----

    @Test
    void testLocalVariable_usage() {
        List<ParsedHit> matching = findHits("EdgeCases", "localVarUsage", "strlen");
        assertFalse(matching.isEmpty(),
                "Expected hit for EdgeCases.localVarUsage — local variable should be taint-tracked");

        ParsedHit h = matching.get(0);
        assertEquals("c", h.lib, "Local variable CLib lib = Native.load(\"c\", ...) should resolve to lib=c");
        assertEquals("strlen", h.symbol);
        assertTrue(h.iface.contains("CLib"), "Interface should be CLib");
    }

    // ---- Cross-JAR tracking ----

    @Test
    void testCallerCalleeJarTracking() {
        // All app classes are in myapp.jar, all interfaces in mylib.jar
        for (ParsedHit h : hits) {
            assertEquals("myapp.jar", h.callerJar,
                    "Caller JAR should be myapp.jar for: " + h.callerSig);
            assertEquals("mylib.jar", h.calleeJar,
                    "Callee JAR should be mylib.jar for: " + h.calleeSig);
        }
    }

    // ---- Total hit count sanity check ----

    @Test
    void testTotalHitCount() {
        // 3 MyApp + 0 WinApp (filtered: kernel32) + 4 EdgeCases = 7
        assertEquals(7, hits.size(),
                "Expected 7 total hits (3 MyApp + 4 EdgeCases, WinApp excluded by platform filter), got: " + hits.size()
                        + "\nHits:\n" + hits.stream().map(h -> "  " + h.callerSig + " | " + h.lib + " | " + h.symbol)
                        .collect(Collectors.joining("\n")));
    }

    // ================ Helpers ================

    /**
     * Finds hits where callerSig contains the caller class name and symbol matches.
     */
    private List<ParsedHit> findHits(String callerClass, String symbol) {
        return hits.stream()
                .filter(h -> h.callerSig.contains(callerClass) && h.symbol.equals(symbol))
                .collect(Collectors.toList());
    }

    /**
     * Finds hits where callerSig contains the caller class name AND method name, and symbol matches.
     */
    private List<ParsedHit> findHits(String callerClass, String methodName, String symbol) {
        return hits.stream()
                .filter(h -> h.callerSig.contains(callerClass)
                        && h.callerSig.contains(methodName)
                        && h.symbol.equals(symbol))
                .collect(Collectors.toList());
    }

    /**
     * Parses the jna_iface_hits.txt output file into structured objects.
     * Format: callerSig | lib | symbol | apiPattern | interface | calleeSig | callerJar | calleeJar
     */
    private static List<ParsedHit> parseHitsFile(File hitsFile) throws IOException {
        List<ParsedHit> parsed = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(hitsFile))) {
            String line;
            while ((line = br.readLine()) != null) {
                line = line.trim();
                // Skip header lines and blanks
                if (line.isEmpty() || line.startsWith("===") || line.startsWith("Format:")) {
                    continue;
                }
                String[] parts = line.split("\\s*\\|\\s*");
                if (parts.length >= 8) {
                    parsed.add(new ParsedHit(
                            parts[0].trim(),
                            parts[1].trim(),
                            parts[2].trim(),
                            parts[3].trim(),
                            parts[4].trim(),
                            parts[5].trim(),
                            parts[6].trim(),
                            parts[7].trim()
                    ));
                }
            }
        }
        return parsed;
    }

    /**
     * Structured representation of a parsed hit line.
     */
    static class ParsedHit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String apiPattern;
        final String iface;
        final String calleeSig;
        final String callerJar;
        final String calleeJar;

        ParsedHit(String callerSig, String lib, String symbol, String apiPattern, String iface,
                   String calleeSig, String callerJar, String calleeJar) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.apiPattern = apiPattern;
            this.iface = iface;
            this.calleeSig = calleeSig;
            this.callerJar = callerJar;
            this.calleeJar = calleeJar;
        }
    }
}
