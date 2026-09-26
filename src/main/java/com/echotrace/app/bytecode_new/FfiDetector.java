package com.echotrace.app.bytecode_new;

import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.echotrace.app.bytecode_new.DetectorSupport.*;

/**
 * FFI (Foreign Function &amp; Memory API) Detector
 *
 * Detects native calls made via Java's Foreign Function &amp; Memory API (Panama):
 *   - Finalized API: java.lang.foreign (Java 22+)
 *   - Incubator API: jdk.incubator.foreign (Java 17-21)
 *
 * Recovers (library, symbol) via taint tracking:
 *   SymbolLookup.libraryLookup("ssl", arena) -&gt; lookup.find("SSL_read")
 *     -&gt; Linker.downcallHandle(addr, desc) -&gt; handle.invokeExact(...)
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.FfiDetector \
 *     -Dexec.args="&lt;target-jars-dir&gt; [outDir]" [-Ddetector.debug=true]
 *
 * Outputs (in outDir, default=current dir):
 *   - ffi_hits.txt
 *   - skipped_methods.txt
 */
public final class FfiDetector {

    // ---- Finalized API (Java 22+) ----
    private static final String FFI_SYMBOL_LOOKUP = "java.lang.foreign.SymbolLookup";
    private static final String FFI_LINKER        = "java.lang.foreign.Linker";
    private static final String FFI_METHOD_HANDLE = "java.lang.invoke.MethodHandle";

    // ---- Incubator API (Java 17-21) ----
    private static final String INC_SYMBOL_LOOKUP  = "jdk.incubator.foreign.SymbolLookup";
    private static final String INC_LIBRARY_LOOKUP = "jdk.incubator.foreign.LibraryLookup";
    private static final String INC_CLINKER        = "jdk.incubator.foreign.CLinker";

    private static final Set<String> SYMBOL_LOOKUP_CLASSES = new HashSet<>(Arrays.asList(
            FFI_SYMBOL_LOOKUP, INC_SYMBOL_LOOKUP, INC_LIBRARY_LOOKUP));
    private static final Set<String> LINKER_CLASSES = new HashSet<>(Arrays.asList(
            FFI_LINKER, INC_CLINKER));

    /** Generic inner-class names that are NOT C symbols. */
    private static final Set<String> GENERIC_INNER_NAMES = new HashSet<>(Arrays.asList(
            "callback", "cb", "dh", "Function", "Holder"));

    private static final String MECHANISM = "downcallHandle";

    // Progress logging
    private static final int  METHOD_TICK  = 50_000;

    /** Max fixed-point iterations for the taint-population pass. */
    private static final int MAX_TAINT_ITERATIONS = 4;

    // ---- Instance taint state (populated in PASS 1, used in PASS 2) ----

    /** SymbolLookup field -> library name */
    private final Map<String, String> fieldToLookupLib = new HashMap<>();
    /** MemorySegment field -> symbol name */
    private final Map<String, String> fieldToSymbol = new HashMap<>();
    /** MethodHandle field -> lib+symbol */
    private final Map<String, FuncInfo> fieldToHandle = new HashMap<>();
    /** Declaring class FQCN -> library name(s), '|'-joined */
    private final Map<String, String> classToLibs = new HashMap<>();
    /** String-typed field -> constant value */
    private final Map<String, String> fieldToString = new HashMap<>();
    /** symbol name -> library basename (built from nm -D on the LIBS dir) */
    private final Map<String, String> libSymbolIndex = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: FfiDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        new FfiDetector().run(AnalysisContext.build(targetDir), out);
    }

    /** Runs over a shared, pre-parsed context (standalone main builds its own). */
    void run(AnalysisContext ctx, File out) throws IOException {
        File hitsFile = new File(out, "ffi_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Build library symbol index from LIBS_* sibling directory
        File libsDir = deriveLibsDir(ctx.targetDir);
        if (libsDir != null) {
            buildLibSymbolIndex(libsDir);
        } else {
            System.out.println("[INFO] no LIBS directory found, callback symbol resolution disabled");
        }

        Map<String, String> classToJar = ctx.classToJarAll;
        List<SootClass> targetClasses = ctx.targetClassesAll; // already outer-first
        System.out.println("[FFI] classes=" + targetClasses.size() + " out=" + out.getAbsolutePath());

        try (
                BufferedWriter hitW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== FFI (Foreign Function & Memory API) Hits ===\n");
            hitW.write("Format: callerSig | lib | symbol | mechanism | jar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions during body building) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();

            long methodsSeen = 0;
            long methodsScanned = 0;
            long hits = 0;
            long skipped = 0;

            // ============================================================
            // PASS 1 (fixed point): populate field/class taints from ALL
            // method bodies — library loading also happens outside <clinit>.
            // ============================================================
            System.out.println("[PASS 1] Populating taints (fixed point, max "
                    + MAX_TAINT_ITERATIONS + " iterations)...");
            for (int iter = 0; iter < MAX_TAINT_ITERATIONS; iter++) {
                int prevLookup = fieldToLookupLib.size();
                int prevSym    = fieldToSymbol.size();
                int prevHandle = fieldToHandle.size();
                int prevLibs   = classToLibs.size();

                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        try {
                            if (!m.hasBody()) continue;
                            analyzeMethod(m, false, null);
                        } catch (LinkageError | RuntimeException e) {
                            if (iter == 0) {
                                skipped++;
                                writeSkip(skipW, m.getSignature().toString(), e);
                            }
                        }
                    }
                }

                System.out.println("[PASS 1." + iter + "] lookupLibs=" + fieldToLookupLib.size()
                        + " symbols=" + fieldToSymbol.size()
                        + " handles=" + fieldToHandle.size()
                        + " classLibs=" + classToLibs.size());

                boolean stable = fieldToLookupLib.size() == prevLookup
                        && fieldToSymbol.size() == prevSym
                        && fieldToHandle.size() == prevHandle
                        && classToLibs.size() == prevLibs;
                if (stable && iter > 0) break;
            }

            // ============================================================
            // PASS 2: Process all methods, collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for FFI hits...");

            Set<String> classesWithHits = new HashSet<>();
            Set<String> hitSymbols = new HashSet<>();

            for (SootClass sc : targetClasses) {
                String fqcn = sc.getType().getFullyQualifiedName();
                String jar = classToJar.getOrDefault(fqcn, "?");

                for (SootMethod m : sc.getMethods()) {
                    methodsSeen++;

                    long now = System.currentTimeMillis();
                    if (methodsSeen % METHOD_TICK == 0) {
                        System.out.println("[PROGRESS] elapsed=" + ((now - start) / 1000) + "s"
                                + " methods=" + methodsSeen
                                + " scanned=" + methodsScanned
                                + " hits=" + hits
                                + " skipped=" + skipped);
                    }

                    try {
                        if (!m.hasBody()) continue;
                        methodsScanned++;

                        for (Hit h : analyzeMethod(m, true, jar)) {
                            hits++;
                            classesWithHits.add(fqcn);
                            hitSymbols.add(h.symbol);
                            hitW.write(h.callerSig + " | " + h.lib + " | " + h.symbol
                                    + " | " + h.mechanism + " | " + h.jar + "\n");
                        }
                    } catch (LinkageError | RuntimeException e) {
                        // LinkageError covers VerifyError, IncompatibleClassChangeError, ...
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }

                // Library-index fallback: for classes whose <clinit> fails with
                // VerifyError (e.g. MemorySegment is final in Java 22+, SootUp
                // can't load it), infer the symbol from the class name and
                // verify it against the container's library exports. Covers
                // jextract inner classes (openssl_h$SSL_read) and callback
                // wrappers (SSL_CTX_set_verify$callback).
                if (!fqcn.endsWith("$Function") && !classesWithHits.contains(fqcn)) {
                    FuncInfo cbInfo = resolveCallbackFromLibs(fqcn);
                    if (cbInfo != null) {
                        hits++;
                        classesWithHits.add(fqcn);
                        hitSymbols.add(cbInfo.sym);
                        hitW.write("<" + fqcn + ": " + cbInfo.sym + "> | " + cbInfo.lib
                                + " | " + cbInfo.sym + " | " + MECHANISM + " | " + jar + "\n");
                    } else if (hasInvokeMethod(sc) && resolveLibForCallbackClass(fqcn) != null) {
                        // Callback typedef class (e.g. pem_password_cb) whose symbol
                        // isn't an exported library function — emit with <?> markers.
                        // The resolveLibForCallbackClass check restricts this to
                        // known FFM packages (not random invoke methods).
                        hits++;
                        classesWithHits.add(fqcn);
                        hitW.write(findInvokeMethodSig(sc) + " | <?> | <?> | "
                                + MECHANISM + " | " + jar + "\n");
                    }
                }
            }

            // ============================================================
            // PASS 3: Method-name fallback for jextract parent classes whose
            // method bodies fail with VerifyError (openssl_h_Compatibility,
            // openssl_h_Macros, ...). These use $<digit>Holder lazy-init inner
            // classes; the parent's method names are C function/macro names.
            // ============================================================
            hits += runPass3(targetClasses, classToJar, classesWithHits, hitSymbols, hitW);

            System.out.println("[INFO] total FFI hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /** PASS 3 (see caller comment). Returns the number of hits added. */
    private int runPass3(List<SootClass> targetClasses, Map<String, String> classToJar,
                         Set<String> classesWithHits, Set<String> hitSymbols,
                         BufferedWriter hitW) throws IOException {
        System.out.println("[PASS 3] Scanning jextract parent classes with Holder inner classes...");

        // Identify jextract parent classes by $<digit>Holder inner classes.
        Set<String> holderParents = new HashSet<>();
        for (SootClass sc : targetClasses) {
            String fqcn = sc.getType().getFullyQualifiedName();
            int dollar = fqcn.lastIndexOf('$');
            if (dollar > 0 && fqcn.substring(dollar + 1).matches("\\d+Holder")) {
                holderParents.add(fqcn.substring(0, dollar));
            }
        }

        // Coverage filter: skip parents where most C-identifier methods are
        // already covered by PASS 2 (avoids duplicating openssl_h).
        Set<String> jextractParents = new HashSet<>();
        for (SootClass sc : targetClasses) {
            String fqcn = sc.getType().getFullyQualifiedName();
            if (!holderParents.contains(fqcn)) continue;
            int total = 0, covered = 0;
            for (SootMethod m : sc.getMethods()) {
                String mn = m.getName();
                if (!isCIdentifierMethod(mn)) continue;
                total++;
                if (hitSymbols.contains(mn)) covered++;
            }
            if (total > 0 && covered < total / 2) {
                jextractParents.add(fqcn);
            }
        }

        if (jextractParents.isEmpty()) {
            System.out.println("[PASS 3] No jextract parent classes found, skipping");
            return 0;
        }

        System.out.println("[PASS 3] Found " + jextractParents.size()
                + " jextract parent classes: " + jextractParents);
        int pass3Hits = 0;

        for (SootClass sc : targetClasses) {
            String fqcn = sc.getType().getFullyQualifiedName();
            if (!jextractParents.contains(fqcn)) continue;

            // If ANY method is an exported library symbol, only emit
            // index-verified methods (avoids false positives from Java helpers
            // like isLibreSSLPre35). If none are (pure macro wrapper class),
            // allow package-based fallback for all methods.
            boolean hasIndexedSymbols = false;
            for (SootMethod check : sc.getMethods()) {
                if (isCIdentifierMethod(check.getName())
                        && libSymbolIndex.containsKey(check.getName())) {
                    hasIndexedSymbols = true;
                    break;
                }
            }

            String jar = classToJar.getOrDefault(fqcn, "?");

            for (SootMethod m : sc.getMethods()) {
                String methodName = m.getName();
                if (!isCIdentifierMethod(methodName)) continue;
                if (hitSymbols.contains(methodName)) continue;

                String lib = resolveLibFromSymbolIndex(methodName);
                if (lib == null && !hasIndexedSymbols) {
                    lib = resolveLibForCallbackClass(fqcn);
                }
                if (lib == null) continue;

                hitSymbols.add(methodName);
                pass3Hits++;
                classesWithHits.add(fqcn);
                hitW.write(m.getSignature() + " | " + lib + " | " + methodName
                        + " | " + MECHANISM + " | " + jar + "\n");
            }
        }
        System.out.println("[PASS 3] Added " + pass3Hits + " hits from method-name scan");
        return pass3Hits;
    }

    /** Plausible C function/macro name: not a constructor/synthetic, valid C identifier. */
    private static boolean isCIdentifierMethod(String name) {
        return !name.startsWith("<") && !name.startsWith("$")
                && name.matches("[A-Za-z_][A-Za-z0-9_]*");
    }

    /**
     * Analyzes a single method for FFI calls.
     *
     * Tracks:
     * - SymbolLookup.libraryLookup / loaderLookup / defaultLookup -> library taint
     * - System.loadLibrary -> class-level library taint
     * - SymbolLookup.find / findOrThrow -> symbol taint
     * - Linker.downcallHandle -> combines lib + symbol into FuncInfo
     * - MethodHandle.invokeExact / invoke -> SINK (hit)
     *
     * Locals are invalidated on redefinition so stale facts never leak.
     *
     * @param m           method to analyze
     * @param collectHits false during taint population (PASS 1), true in PASS 2
     * @param jar         jar basename (PASS 2 only)
     * @return list of hits (empty during PASS 1)
     */
    private List<Hit> analyzeMethod(SootMethod m, boolean collectHits, String jar) {
        Map<Local, String> localToLookupLib = new HashMap<>();   // SymbolLookup -> lib
        Map<Local, String> localToSymbol    = new HashMap<>();   // MemorySegment -> symbol
        Map<Local, FuncInfo> localToHandle  = new HashMap<>();   // MethodHandle -> lib+sym
        Map<Local, String> localToString    = new HashMap<>();   // String locals
        List<Hit> hits = collectHits ? new ArrayList<>() : Collections.emptyList();

        String callerClass = m.getDeclaringClassType().getFullyQualifiedName();
        String traceDowncallSymbol = null; // jextract traceDowncall fallback

        for (Stmt stmt : m.getBody().getStmts()) {

            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                // ---- CASE 1: local = something ----
                if (lhs instanceof Local) {
                    Local l = (Local) lhs;

                    // Compute new facts from the RHS first...
                    String newString = null, newLookupLib = null, newSymbol = null;
                    FuncInfo newHandle = null;

                    if (rhs instanceof StringConstant) {
                        newString = ((StringConstant) rhs).getValue();
                    } else if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        newString = localToString.get(r);
                        newLookupLib = localToLookupLib.get(r);
                        newSymbol = localToSymbol.get(r);
                        newHandle = localToHandle.get(r);
                    } else if (rhs instanceof JFieldRef) {
                        String fkey = fieldKey((JFieldRef) rhs);
                        newString = fieldToString.get(fkey);
                        newLookupLib = fieldToLookupLib.get(fkey);
                        newSymbol = fieldToSymbol.get(fkey);
                        newHandle = fieldToHandle.get(fkey);
                    } else {
                        AbstractInvokeExpr inv = asInvoke(rhs);
                        if (inv != null) {
                            MethodSignature sig = inv.getMethodSignature();
                            String decl = sig.getDeclClassType().getFullyQualifiedName();
                            String name = sig.getName();

                            // --- Library loading ---
                            if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "libraryLookup".equals(name)) {
                                newLookupLib = resolveStringArg(inv, localToString, 0);
                            } else if (INC_LIBRARY_LOOKUP.equals(decl) && "ofDefault".equals(name)) {
                                newLookupLib = "<default-c-lib>";
                            } else if (INC_LIBRARY_LOOKUP.equals(decl) && "ofPath".equals(name)) {
                                String path = resolveStringArg(inv, localToString, 0);
                                newLookupLib = (path != null) ? path : "<?>";
                            } else if (LINKER_CLASSES.contains(decl) && "defaultLookup".equals(name)) {
                                newLookupLib = "<default-c-lib>";
                            } else if (INC_CLINKER.equals(decl) && "getInstance".equals(name)) {
                                newLookupLib = "<default-c-lib>";
                            } else if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "loaderLookup".equals(name)) {
                                newLookupLib = "<loader>";
                            } else if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "or".equals(name)) {
                                newLookupLib = resolveOrLookup(inv, localToLookupLib);
                            }

                            // System.mapLibraryName(name) — pass through input
                            else if ("java.lang.System".equals(decl) && "mapLibraryName".equals(name)) {
                                newString = resolveStringArg(inv, localToString, 0);
                            }
                            // System.getProperty(key, default) — track the default
                            else if ("java.lang.System".equals(decl) && "getProperty".equals(name)) {
                                newString = resolveGetPropertyDefault(inv, localToString);
                            }

                            // --- Symbol lookup ---
                            else if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "find".equals(name)) {
                                newSymbol = resolveStringArg(inv, localToString, 0);
                            } else if ("findOrThrow".equals(name)) {
                                // jextract helper: any findOrThrow(String) -> MemorySegment
                                newSymbol = resolveFindOrThrow(inv, localToString, decl, callerClass);
                            } else if (INC_LIBRARY_LOOKUP.equals(decl) && "lookup".equals(name)) {
                                newSymbol = resolveStringArg(inv, localToString, 0);
                            }
                            // Optional.orElseThrow / get (unwrap Optional<MemorySegment>)
                            else if ("java.util.Optional".equals(decl)
                                    && ("orElseThrow".equals(name) || "get".equals(name))) {
                                Local base = getInvokeBaseLocal(inv);
                                if (base != null) newSymbol = localToSymbol.get(base);
                            }

                            // --- Downcall handle creation (both APIs) ---
                            else if ((LINKER_CLASSES.contains(decl) || INC_CLINKER.equals(decl))
                                    && "downcallHandle".equals(name)) {
                                newHandle = resolveDowncallInfo(inv, localToSymbol, callerClass);
                            }

                            // --- Side effects (no local fact) ---
                            if ("java.lang.System".equals(decl) && "loadLibrary".equals(name)) {
                                String lib = resolveStringArg(inv, localToString, 0);
                                if (lib != null) mergeClassLib(callerClass, lib);
                            }
                            if ("traceDowncall".equals(name)) {
                                String sym = resolveStringArg(inv, localToString, 0);
                                if (sym != null) traceDowncallSymbol = sym;
                            }
                        }
                    }

                    // ...then invalidate the redefined local, then store.
                    localToString.remove(l);
                    localToLookupLib.remove(l);
                    localToSymbol.remove(l);
                    localToHandle.remove(l);
                    if (newString != null) localToString.put(l, newString);
                    if (newLookupLib != null) localToLookupLib.put(l, newLookupLib);
                    if (newSymbol != null) localToSymbol.put(l, newSymbol);
                    if (newHandle != null) localToHandle.put(l, newHandle);
                }

                // ---- CASE 2: field = something (putstatic/putfield) ----
                if (lhs instanceof JFieldRef) {
                    String fkey = fieldKey((JFieldRef) lhs);

                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().getFullyQualifiedName();
                        String name = sig.getName();

                        if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "libraryLookup".equals(name)) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                fieldToLookupLib.put(fkey, lib);
                                mergeClassLib(callerClass, lib);
                            }
                        } else if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "loaderLookup".equals(name)) {
                            fieldToLookupLib.put(fkey, "<loader>");
                        } else if (LINKER_CLASSES.contains(decl) && "defaultLookup".equals(name)) {
                            fieldToLookupLib.put(fkey, "<default-c-lib>");
                        } else if (SYMBOL_LOOKUP_CLASSES.contains(decl) && "or".equals(name)) {
                            String lib = resolveOrLookup(inv, localToLookupLib);
                            if (lib != null) {
                                fieldToLookupLib.put(fkey, lib);
                                if (!lib.startsWith("<")) mergeClassLib(callerClass, lib);
                            }
                        } else if ((SYMBOL_LOOKUP_CLASSES.contains(decl) && "find".equals(name))
                                || "findOrThrow".equals(name)) {
                            String sym = "findOrThrow".equals(name)
                                    ? resolveFindOrThrow(inv, localToString, decl, callerClass)
                                    : resolveStringArg(inv, localToString, 0);
                            if (sym != null) fieldToSymbol.put(fkey, sym);
                        } else if ((LINKER_CLASSES.contains(decl) || INC_CLINKER.equals(decl))
                                && "downcallHandle".equals(name)) {
                            fieldToHandle.put(fkey, resolveDowncallInfo(inv, localToSymbol, callerClass));
                        } else if ("java.lang.System".equals(decl) && "getProperty".equals(name)) {
                            String def = resolveGetPropertyDefault(inv, localToString);
                            if (def != null) fieldToString.put(fkey, def);
                        }
                    }

                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        String lookupLib = localToLookupLib.get(r);
                        if (lookupLib != null) {
                            fieldToLookupLib.put(fkey, lookupLib);
                            if (!lookupLib.startsWith("<")) mergeClassLib(callerClass, lookupLib);
                        }
                        String sym = localToSymbol.get(r);
                        if (sym != null) fieldToSymbol.put(fkey, sym);
                        FuncInfo fi = localToHandle.get(r);
                        if (fi != null) fieldToHandle.put(fkey, fi);
                        String str = localToString.get(r);
                        if (str != null) fieldToString.put(fkey, str);
                    }

                    if (rhs instanceof StringConstant) {
                        fieldToString.put(fkey, ((StringConstant) rhs).getValue());
                    }
                }
            }

            // ---- Standalone side effects + SINK (single unified block:
            //      handles both `$r = h.invokeExact(...)` and void calls) ----
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature sinkSig = inv.getMethodSignature();
            String decl = sinkSig.getDeclClassType().getFullyQualifiedName();
            String name = sinkSig.getName();

            if ("java.lang.System".equals(decl) && "loadLibrary".equals(name)) {
                String lib = resolveStringArg(inv, localToString, 0);
                if (lib != null) mergeClassLib(callerClass, lib);
            }
            if ("traceDowncall".equals(name)) {
                String sym = resolveStringArg(inv, localToString, 0);
                if (sym != null) traceDowncallSymbol = sym;
            }

            if (FFI_METHOD_HANDLE.equals(decl)
                    && ("invokeExact".equals(name) || "invoke".equals(name))) {
                FuncInfo fi = resolveHandleInfo(inv, localToHandle);
                if (fi == null) continue; // not an FFI MethodHandle

                if (collectHits) {
                    String lib = (fi.lib != null) ? fi.lib : "<?>";
                    String sym = (fi.sym != null) ? fi.sym : "<?>";
                    if ("<?>".equals(sym) && traceDowncallSymbol != null) {
                        sym = traceDowncallSymbol;
                    }
                    hits.add(new Hit(m.getSignature().toString(), lib, sym, MECHANISM, jar));
                }
                traceDowncallSymbol = null;
            }
        }

        return hits;
    }

    // ---- Resolution helpers ----

    /**
     * lookup.or(other): prefer whichever side carries a real library name
     * (not a "&lt;...&gt;" placeholder); fall back to the base's value.
     */
    private static String resolveOrLookup(AbstractInvokeExpr inv, Map<Local, String> localToLookupLib) {
        Local base = getInvokeBaseLocal(inv);
        String baseLib = (base != null) ? localToLookupLib.get(base) : null;
        if (baseLib != null && !baseLib.startsWith("<")) return baseLib;

        List<Immediate> args = inv.getArgs();
        if (!args.isEmpty() && args.get(0) instanceof Local) {
            String argLib = localToLookupLib.get(args.get(0));
            if (argLib != null && !argLib.startsWith("<")) return argLib;
        }
        return baseLib;
    }

    /** System.getProperty(key, default): track the constant default, if any. */
    private static String resolveGetPropertyDefault(AbstractInvokeExpr inv, Map<Local, String> localToString) {
        List<Immediate> args = inv.getArgs();
        if (args.size() < 2) return null; // 1-arg version: not statically resolvable
        Immediate def = args.get(1);
        if (def instanceof StringConstant) return ((StringConstant) def).getValue();
        if (def instanceof Local) return localToString.get(def);
        return null;
    }

    /**
     * findOrThrow("sym"): resolves the symbol and propagates the library from
     * the helper's declaring class (e.g. openssl_h loaded "ssl" -> caller
     * inherits it).
     */
    private String resolveFindOrThrow(AbstractInvokeExpr inv, Map<Local, String> localToString,
                                      String declClass, String callerClass) {
        String sym = resolveStringArg(inv, localToString, 0);
        if (sym != null) {
            String libFromClass = classToLibs.get(declClass);
            if (libFromClass != null) mergeClassLib(callerClass, libFromClass);
        }
        return sym;
    }

    /**
     * Shared lib+symbol resolution for Linker/CLinker.downcallHandle (used for
     * both local and field assignment targets).
     */
    private FuncInfo resolveDowncallInfo(AbstractInvokeExpr inv, Map<Local, String> localToSymbol,
                                         String callerClass) {
        String sym = null;
        String lib = null;

        List<Immediate> args = inv.getArgs();
        boolean addrIsLocal = !args.isEmpty() && args.get(0) instanceof Local;
        if (addrIsLocal) {
            // Field-based addresses are already covered: a getstatic load
            // propagates fieldToSymbol into localToSymbol before this point.
            sym = localToSymbol.get(args.get(0));
        } else {
            // Descriptor-only downcall (jextract callback wrapper): infer from class name
            FuncInfo cbInfo = resolveCallbackFromLibs(callerClass);
            if (cbInfo != null) {
                sym = cbInfo.sym;
                lib = cbInfo.lib;
            }
        }

        // Library: class-level taint, then the container's symbol index,
        // then the callback-package fallback.
        if (lib == null) lib = resolveLibForClass(callerClass);
        if (lib == null && sym != null) lib = resolveLibFromSymbolIndex(sym);
        if (lib == null && !addrIsLocal) lib = resolveLibForCallbackClass(callerClass);

        if (DEBUG) System.out.println("[DBG] downcallHandle: lib=" + lib + ", sym=" + sym);
        return new FuncInfo(lib, sym);
    }

    /** Handle taint for an invokeExact/invoke receiver: local first, then fields. */
    private FuncInfo resolveHandleInfo(AbstractInvokeExpr inv, Map<Local, FuncInfo> localToHandle) {
        Local base = getInvokeBaseLocal(inv);
        if (base != null) {
            FuncInfo fi = localToHandle.get(base);
            if (fi != null) return fi;
        }
        return inv.getUses()
                .filter(v -> v instanceof JFieldRef)
                .map(v -> fieldToHandle.get(fieldKey((JFieldRef) v)))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /** classToLibs for the class, falling back to its outermost class. */
    private String resolveLibForClass(String callerClass) {
        String lib = classToLibs.get(callerClass);
        if (lib != null) return lib;
        int dollar = callerClass.indexOf('$');
        return (dollar > 0) ? classToLibs.get(callerClass.substring(0, dollar)) : null;
    }

    /** "libssl.so.3" -> "ssl" */
    private static String stripLibFileName(String libFile) {
        String lib = libFile;
        if (lib.startsWith("lib")) lib = lib.substring(3);
        int dotSo = lib.indexOf(".so");
        if (dotSo > 0) lib = lib.substring(0, dotSo);
        return lib;
    }

    /** Looks up a symbol in the container's export index; normalized lib name or null. */
    private String resolveLibFromSymbolIndex(String sym) {
        String libFile = libSymbolIndex.get(sym);
        return (libFile != null) ? stripLibFileName(libFile) : null;
    }

    /**
     * Infers the native symbol name from a jextract-generated class name:
     *   openssl_h$SSL_read          -> "SSL_read"  (inner part is the C symbol)
     *   SSL_CTX_set_verify$callback -> "SSL_CTX_set_verify" (outer part; inner is generic)
     *   pem_password_cb             -> "pem_password_cb" (top-level typedef)
     */
    private static String inferCallbackSymbol(String callerClass) {
        if (callerClass == null) return null;
        int lastDot = callerClass.lastIndexOf('.');
        String simple = (lastDot >= 0) ? callerClass.substring(lastDot + 1) : callerClass;
        int dollar = simple.indexOf('$');
        if (dollar > 0) {
            String outer = simple.substring(0, dollar);
            String inner = simple.substring(dollar + 1);
            return (GENERIC_INNER_NAMES.contains(inner) || inner.matches("\\d+Holder"))
                    ? outer : inner;
        }
        return simple;
    }

    /**
     * Verifies the class-name-derived candidate symbol against the container's
     * library exports; FuncInfo(lib, sym) or null.
     */
    private FuncInfo resolveCallbackFromLibs(String callerClass) {
        if (callerClass == null || libSymbolIndex.isEmpty()) return null;
        String candidate = inferCallbackSymbol(callerClass);
        if (candidate == null) return null;
        String libFile = libSymbolIndex.get(candidate);
        return (libFile != null) ? new FuncInfo(stripLibFileName(libFile), candidate) : null;
    }

    /**
     * Package-based library fallback for jextract callback wrapper classes.
     * Currently knows the Tomcat OpenSSL package; extend as needed.
     */
    private String resolveLibForCallbackClass(String callerClass) {
        if (callerClass != null && callerClass.startsWith("org.apache.tomcat.util.openssl.")) {
            String lib = classToLibs.get("org.apache.tomcat.util.openssl.openssl_h");
            return (lib != null) ? lib : "ssl";
        }
        return null;
    }

    /**
     * Merges a library name into classToLibs ('|'-joined set semantics; exact
     * token match, not substring — "ssl" must not match inside "openssl").
     */
    private void mergeClassLib(String className, String lib) {
        String existing = classToLibs.get(className);
        if (existing == null) {
            classToLibs.put(className, lib);
        } else if (!Arrays.asList(existing.split("\\|")).contains(lib)) {
            classToLibs.put(className, existing + "|" + lib);
        }
    }

    /** Callback trampoline pattern used by jextract for callback typedefs. */
    private static boolean hasInvokeMethod(SootClass sc) {
        for (SootMethod m : sc.getMethods()) {
            if ("invoke".equals(m.getName())) return true;
        }
        return false;
    }

    private static String findInvokeMethodSig(SootClass sc) {
        for (SootMethod m : sc.getMethods()) {
            if ("invoke".equals(m.getName())) return m.getSignature().toString();
        }
        return "<" + sc.getType().getFullyQualifiedName() + ": invoke>";
    }

    // ---- Library symbol index (built from nm -D on the LIBS dir) ----

    /**
     * Derives the LIBS directory from the JARFILES directory by convention:
     * JARFILES_&lt;app&gt; -> LIBS_&lt;app&gt; in the same parent directory.
     */
    private static File deriveLibsDir(String jarFilesDir) {
        File jarDir = new File(jarFilesDir);
        String name = jarDir.getName();
        if (name.startsWith("JARFILES_")) {
            File libsDir = new File(jarDir.getParentFile(), "LIBS_" + name.substring("JARFILES_".length()));
            if (libsDir.isDirectory()) return libsDir;
        }
        File parent = jarDir.getParentFile();
        if (parent != null) {
            File[] siblings = parent.listFiles((d, n) -> n.startsWith("LIBS_") && new File(d, n).isDirectory());
            if (siblings != null && siblings.length == 1) return siblings[0];
        }
        return null;
    }

    /**
     * Builds a symbol -> library-basename index by running nm -D on each .so.
     * Files are processed in sorted order so shared symbols resolve
     * deterministically across runs. Versioned suffixes are stripped
     * (SSL_read@@OPENSSL_3.0.0 -> SSL_read).
     */
    private void buildLibSymbolIndex(File libsDir) {
        File[] soFiles = libsDir.listFiles(f -> f.isFile()
                && f.getName().contains(".so")
                && !f.getName().endsWith(".debug"));
        if (soFiles == null || soFiles.length == 0) return;
        Arrays.sort(soFiles); // deterministic first-wins for shared symbols

        for (File so : soFiles) {
            try {
                ProcessBuilder pb = new ProcessBuilder("nm", "-D", "--defined-only", so.getAbsolutePath());
                pb.redirectErrorStream(true);
                Process proc = pb.start();
                try (BufferedReader br = new BufferedReader(
                        new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        // Format: "addr T symbolname" or "addr T symbolname@@VERSION"
                        String[] parts = line.trim().split("\\s+", 3);
                        if (parts.length < 3) continue;
                        if ("U".equalsIgnoreCase(parts[1])) continue; // undefined refs
                        String sym = parts[2];
                        int at = sym.indexOf('@');
                        if (at > 0) sym = sym.substring(0, at);
                        libSymbolIndex.putIfAbsent(sym, so.getName());
                    }
                }
                int exit = proc.waitFor();
                if (exit != 0) {
                    System.err.println("[WARN] nm exited " + exit + " for " + so.getName());
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return;
            } catch (Exception e) {
                System.err.println("[WARN] nm failed for " + so.getName() + ": " + e.getMessage());
            }
        }
        System.out.println("[INFO] libSymbolIndex: " + libSymbolIndex.size()
                + " symbols from " + soFiles.length + " libraries in " + libsDir.getName());
    }

    // ---- Data classes ----

    private static final class FuncInfo {
        final String lib;
        final String sym;

        FuncInfo(String lib, String sym) {
            this.lib = lib;
            this.sym = sym;
        }
    }

    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String mechanism;
        final String jar;

        Hit(String callerSig, String lib, String symbol, String mechanism, String jar) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.mechanism = mechanism;
            this.jar = jar;
        }
    }
}