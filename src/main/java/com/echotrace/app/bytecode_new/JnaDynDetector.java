package com.echotrace.app.bytecode_new;

import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.ref.JParameterRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JIdentityStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

import static com.echotrace.app.bytecode_new.DetectorSupport.*;

/**
 * JNA Dynamic Use Detector (Target-only analysis)
 *
 * Detects dynamic JNA boundary calls:
 *   com.sun.jna.Function.invoke*
 *
 * Recovers (library, symbol) when constant:
 *   NativeLibrary.getInstance("c") -> getFunction("strlen") -> Function.invoke*()
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaDynDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]" \
 *     [-Ddetector.runtime.dir=<extra-classpath-dir>] [-Ddetector.debug=true]
 *
 * Outputs (in outDir):
 *   - jna_dyn_hits.txt
 *   - skipped_methods.txt
 */
public final class JnaDynDetector {

    private static final String JNA_NATIVE_LIBRARY = "com.sun.jna.NativeLibrary";
    private static final String JNA_FUNCTION       = "com.sun.jna.Function";

    // JNA library prefix — hits from these classes are JNA framework/platform
    // code, not app FFI. NOTE: unlike the other detectors, com.sun.jna.* classes
    // ARE analyzed here (their field taints matter), only their hits are filtered.
    private static final String JNA_CORE_PREFIX = "com.sun.jna.";

    // API pattern constants for classification (one per overload)
    private static final String API_NATIVELIB_GETFUNCTION          = "NativeLibrary.getFunction";
    private static final String API_FN_GETFUNCTION_PTR             = "Function.getFunction(Pointer)";
    private static final String API_FN_GETFUNCTION_PTR_INT         = "Function.getFunction(Pointer,int)";
    private static final String API_FN_GETFUNCTION_STR_STR         = "Function.getFunction(String,String)";
    private static final String API_FN_GETFUNCTION_STR_STR_INT     = "Function.getFunction(String,String,int)";
    private static final String API_FN_GETFUNCTION_STR_STR_INT_STR = "Function.getFunction(String,String,int,String)";
    private static final String API_UNKNOWN                        = "<?>";

    // Progress logging intervals
    private static final int  METHOD_TICK  = 50_000;

    /** Max fixed-point iterations for the taint/summary population pass. */
    private static final int MAX_TAINT_ITERATIONS = 4;

    // Instance state (no mutable statics: reusable, testable, no cross-run leakage).

    /** field signature -> library name (e.g. LIB = NativeLibrary.getInstance("c")) */
    private final Map<String, String> fieldToLib = new HashMap<>();
    /** field signature -> FuncInfo (e.g. STRLEN = LIB.getFunction("strlen")) */
    private final Map<String, FuncInfo> fieldToFunc = new HashMap<>();
    /** method signature -> constant String it returns */
    private final Map<String, String> methodStringReturns = new HashMap<>();
    /** method signature -> Function summary it returns */
    private final Map<String, FuncSummary> methodFuncReturns = new HashMap<>();
    /** method signature -> library name of the NativeLibrary it returns */
    private final Map<String, String> methodNativeLibReturns = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnaDynDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : deriveDefaultOutDir(targetDir);

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        new JnaDynDetector().run(AnalysisContext.build(targetDir), out);
    }

    /** Runs over a shared, pre-parsed context (standalone main builds its own). */
    void run(AnalysisContext ctx, File out) throws IOException {
        File hitsFile = new File(out, "jna_dyn_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Intentionally uses ALL classes (com.sun.jna.* taints matter;
        // their hits are filtered in PASS 2).
        Map<String, String> nativeLibraryNames = ctx.nativeLibraryNames;
        List<SootClass> targetClasses = ctx.targetClassesAll;
        System.out.println("[DYN] classes=" + targetClasses.size() + " out=" + out.getAbsolutePath());

        try (
                BufferedWriter hitW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== JNA Dynamic Hits (Function.invoke*) ===\n");
            hitW.write("Format: callerSig | lib | symbol | apiPattern | sinkSig | stmt\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions during body building) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();

            long methodsSeen = 0;
            long methodsScanned = 0;
            long hits = 0;
            long jnaInternalFiltered = 0;
            long skipped = 0;

            // ============================================================
            // PASS 1 (fixed point): summarize helpers AND populate field
            // taints from ALL method bodies — not just <clinit>, since LIB /
            // FUNC fields are also assigned in constructors and init helpers.
            // Summaries and field taints feed each other:
            //   private static Function lookup(String n) { return LIB.getFunction(n); }
            // needs LIB's taint, and <clinit> FUNC = lookup("fstat") needs the
            // summary — so iterate until stable (capped).
            // ============================================================
            System.out.println("[PASS 1] Populating summaries + field taints (fixed point, max "
                    + MAX_TAINT_ITERATIONS + " iterations)...");

            for (int iter = 0; iter < MAX_TAINT_ITERATIONS; iter++) {
                int prevStr  = methodStringReturns.size();
                int prevFn   = methodFuncReturns.size();
                int prevNl   = methodNativeLibReturns.size();
                int prevFLib = fieldToLib.size();
                int prevFFn  = fieldToFunc.size();

                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        try {
                            if (!m.hasBody()) continue;
                            String sig = m.getSignature().toString();

                            if (!methodStringReturns.containsKey(sig)) {
                                String s = summarizeStringReturn(m);
                                if (s != null) methodStringReturns.put(sig, s);
                            }
                            if (!methodFuncReturns.containsKey(sig)) {
                                FuncSummary fs = summarizeFunctionReturn(m);
                                if (fs != null) methodFuncReturns.put(sig, fs);
                            }
                            if (!methodNativeLibReturns.containsKey(sig)) {
                                String lib = summarizeNativeLibraryReturn(m);
                                if (lib != null) methodNativeLibReturns.put(sig, lib);
                            }

                            // Field taint side effects only (no hit collection)
                            analyzeMethod(m, false);
                        } catch (VerifyError | RuntimeException e) {
                            if (iter == 0) {
                                skipped++;
                                writeSkip(skipW, m.getSignature().toString(), e);
                            }
                        }
                    }
                }

                System.out.println("[PASS 1." + iter + "] strings=" + methodStringReturns.size()
                        + " funcSummaries=" + methodFuncReturns.size()
                        + " nativeLibSummaries=" + methodNativeLibReturns.size()
                        + " fieldLibs=" + fieldToLib.size()
                        + " fieldFuncs=" + fieldToFunc.size());

                boolean stable = methodStringReturns.size() == prevStr
                        && methodFuncReturns.size() == prevFn
                        && methodNativeLibReturns.size() == prevNl
                        && fieldToLib.size() == prevFLib
                        && fieldToFunc.size() == prevFFn;
                if (stable && iter > 0) break;
            }

            // ============================================================
            // PASS 2: Process all methods and collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for JNA hits...");
            for (SootClass sc : targetClasses) {
                // JNA framework internals (e.g. Function.invokeDouble ->
                // Function.invoke) are internal delegation, not app FFI
                // crossings: analyze for taint, but do not report hits.
                String fqcn = sc.getType().getFullyQualifiedName();
                boolean isJnaInternal = fqcn.startsWith(JNA_CORE_PREFIX);

                for (SootMethod m : sc.getMethods()) {
                    methodsSeen++;

                    long now = System.currentTimeMillis();
                    if (methodsSeen % METHOD_TICK == 0) {
                        System.out.println("[PROGRESS] elapsed=" + ((now - start) / 1000) + "s"
                                + " targetClasses=" + targetClasses.size()
                                + " methodsSeen=" + methodsSeen
                                + " methodsScanned=" + methodsScanned
                                + " hits=" + hits
                                + " skipped=" + skipped);
                    }

                    try {
                        if (!m.hasBody()) continue;
                        methodsScanned++;

                        List<Hit> found = analyzeMethod(m, true);
                        if (found.isEmpty()) continue;

                        if (isJnaInternal) {
                            jnaInternalFiltered += found.size();
                        } else {
                            for (Hit h : found) {
                                hits++;
                                hitW.write(h.callerSig + " | "
                                        + NativeLibraryNames.resolve(h.lib, nativeLibraryNames) + " | "
                                        + h.symbol + " | "
                                        + h.apiPattern + " | "
                                        + h.sinkSig + " | "
                                        + h.stmt + "\n");
                            }
                        }
                    } catch (VerifyError | RuntimeException e) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }
            }

            System.out.println("[INFO] total dynamic-JNA hits: " + hits);
            System.out.println("[INFO] JNA-internal filtered:  " + jnaInternalFiltered);
            System.out.println("[INFO] skipped methods (errors/verify): " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Analyzes a single method for JNA dynamic calls.
     *
     * Performs intra-procedural taint tracking to resolve library and symbol
     * names for JNA Function.invoke* calls. Tracks:
     * - NativeLibrary.getInstance("lib") mapping locals/fields to library names
     * - NativeLibrary.getFunction("sym") / Function.getFunction(...) mapping
     *   locals/fields to function info
     * - Local-to-local and local-to-field propagation
     * - Field loads (getstatic/getfield) to recover taint from fields
     *
     * Locals are invalidated on redefinition, so a stale constant from an
     * earlier assignment can never leak into a later use.
     *
     * @param m           method to analyze
     * @param collectHits false during taint population (PASS 1), true in PASS 2
     * @return list of hits (empty during PASS 1)
     */
    private List<Hit> analyzeMethod(SootMethod m, boolean collectHits) {
        Map<Local, String> nlToLib = new HashMap<>();
        Map<Local, FuncInfo> fnToInfo = new HashMap<>();
        Map<Local, String> localToString = new HashMap<>();
        List<Hit> hits = collectHits ? new ArrayList<>() : Collections.emptyList();

        for (Stmt stmt : m.getBody().getStmts()) {

            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                // ---- CASE 1: local = something ----
                if (lhs instanceof Local) {
                    Local l = (Local) lhs;

                    // Compute the new facts from the RHS first (before
                    // invalidating, in case rhs aliases lhs)...
                    String newString = null;
                    String newLib = null;
                    FuncInfo newFunc = null;

                    if (rhs instanceof StringConstant) {
                        newString = ((StringConstant) rhs).getValue();
                    } else if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        newString = localToString.get(r);
                        newLib = nlToLib.get(r);
                        newFunc = fnToInfo.get(r);
                    } else if (rhs instanceof JFieldRef) {
                        String fkey = fieldKey((JFieldRef) rhs);
                        newLib = fieldToLib.get(fkey);
                        newFunc = fieldToFunc.get(fkey);
                    } else {
                        AbstractInvokeExpr inv = asInvoke(rhs);
                        if (inv != null) {
                            MethodSignature sig = inv.getMethodSignature();
                            String decl = sig.getDeclClassType().getFullyQualifiedName();
                            String name = sig.getName();

                            newString = methodStringReturns.get(sig.toString());
                            newLib = methodNativeLibReturns.get(sig.toString());

                            FuncSummary returnedFunc = methodFuncReturns.get(sig.toString());
                            if (returnedFunc != null) {
                                newFunc = returnedFunc.instantiate(inv, localToString, fieldToLib);
                            }

                            // nl = NativeLibrary.getInstance("c")
                            if (JNA_NATIVE_LIBRARY.equals(decl) && "getInstance".equals(name)) {
                                String lib = resolveStringArg(inv, localToString, 0);
                                if (lib != null) newLib = lib;
                            }

                            // fn = nl.getFunction("strlen")
                            if (JNA_NATIVE_LIBRARY.equals(decl) && "getFunction".equals(name)) {
                                String lib = resolveLibFromInvokeBase(inv, nlToLib);
                                String sym = resolveStringArg(inv, localToString, 0);
                                newFunc = new FuncInfo(lib, sym, API_NATIVELIB_GETFUNCTION);
                            }

                            // fn = Function.getFunction(...) -- 5 static overloads
                            if (JNA_FUNCTION.equals(decl) && "getFunction".equals(name)) {
                                newFunc = classifyFunctionGetFunction(inv, localToString);
                            }
                        }
                    }

                    // ...then invalidate the redefined local...
                    nlToLib.remove(l);
                    fnToInfo.remove(l);
                    localToString.remove(l);

                    // ...then record the new facts.
                    if (newString != null) localToString.put(l, newString);
                    if (newLib != null) nlToLib.put(l, newLib);
                    if (newFunc != null) fnToInfo.put(l, newFunc);
                }

                // ---- CASE 2: field = something (putstatic/putfield) ----
                if (lhs instanceof JFieldRef) {
                    String fkey = fieldKey((JFieldRef) lhs);

                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().getFullyQualifiedName();
                        String name = sig.getName();

                        FuncSummary returnedFunc = methodFuncReturns.get(sig.toString());
                        if (returnedFunc != null) {
                            fieldToFunc.put(fkey, returnedFunc.instantiate(inv, localToString, fieldToLib));
                        }

                        String returnedNativeLib = methodNativeLibReturns.get(sig.toString());
                        if (returnedNativeLib != null) {
                            fieldToLib.put(fkey, returnedNativeLib);
                        }

                        // FIELD = NativeLibrary.getInstance("c")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && "getInstance".equals(name)) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) {
                                fieldToLib.put(fkey, lib);
                                if (DEBUG) System.out.println("[DBG] fieldToLib: " + fkey + " -> " + lib);
                            }
                        }

                        // FIELD = nl.getFunction("sym")
                        if (JNA_NATIVE_LIBRARY.equals(decl) && "getFunction".equals(name)) {
                            String lib = resolveLibFromInvokeBase(inv, nlToLib);
                            String sym = resolveStringArg(inv, localToString, 0);
                            fieldToFunc.put(fkey, new FuncInfo(lib, sym, API_NATIVELIB_GETFUNCTION));
                            if (DEBUG) System.out.println("[DBG] fieldToFunc: " + fkey + " -> (" + lib + ", " + sym + ")");
                        }

                        // FIELD = Function.getFunction(...) -- 5 static overloads
                        if (JNA_FUNCTION.equals(decl) && "getFunction".equals(name)) {
                            FuncInfo fi = classifyFunctionGetFunction(inv, localToString);
                            fieldToFunc.put(fkey, fi);
                            if (DEBUG) System.out.println("[DBG] fieldToFunc (static factory): " + fkey
                                    + " -> (" + fi.lib + ", " + fi.sym + ", " + fi.apiPattern + ")");
                        }
                    }

                    // field = local
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        String lib = nlToLib.get(r);
                        if (lib != null) fieldToLib.put(fkey, lib);
                        FuncInfo fi = fnToInfo.get(r);
                        if (fi != null) fieldToFunc.put(fkey, fi);
                    }
                }
            }

            // ---- Handle sink: Function.invoke* ----
            if (!collectHits) continue;

            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature sinkSig = inv.getMethodSignature();
            if (JNA_FUNCTION.equals(sinkSig.getDeclClassType().getFullyQualifiedName())
                    && sinkSig.getName().startsWith("invoke")) {
                FuncInfo fi = resolveFuncInfoFromInvoke(inv, fnToInfo);

                String lib = (fi != null && fi.lib != null) ? fi.lib : "<?>";
                String sym = (fi != null && fi.sym != null) ? fi.sym : "<?>";
                String api = (fi != null && fi.apiPattern != null) ? fi.apiPattern : API_UNKNOWN;

                hits.add(new Hit(
                        m.getSignature().toString(),
                        lib,
                        sym,
                        api,
                        sinkSig.toString(),
                        stmt.toString()
                ));
            }
        }

        return hits;
    }

    /**
     * Resolves the library name from an invoke expression's receiver:
     * tainted local first, then field references among the uses.
     */
    private String resolveLibFromInvokeBase(AbstractInvokeExpr inv, Map<Local, String> nlToLib) {
        Local base = getInvokeBaseLocal(inv);
        if (base != null) {
            String lib = nlToLib.get(base);
            if (lib != null) return lib;
        }

        return inv.getUses()
                .filter(v -> v instanceof JFieldRef)
                .map(v -> fieldToLib.get(fieldKey((JFieldRef) v)))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /**
     * Resolves the function info (library + symbol) for a Function.invoke*
     * receiver: tainted local first, then field references among the uses.
     */
    private FuncInfo resolveFuncInfoFromInvoke(AbstractInvokeExpr inv, Map<Local, FuncInfo> fnToInfo) {
        Local base = getInvokeBaseLocal(inv);
        if (base != null) {
            FuncInfo fi = fnToInfo.get(base);
            if (fi != null) return fi;
        }

        return inv.getUses()
                .filter(v -> v instanceof JFieldRef)
                .map(v -> fieldToFunc.get(fieldKey((JFieldRef) v)))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    /**
     * Classifies a Function.getFunction(...) static invoke and extracts args.
     *
     * 5 overloads, each mapped to its own API pattern:
     *   1. getFunction(Pointer p)                                            -> NOT resolvable
     *   2. getFunction(Pointer p, int callFlags)                             -> NOT resolvable
     *   3. getFunction(String libraryName, String functionName)              -> resolvable
     *   4. getFunction(String libraryName, String functionName, int)         -> resolvable
     *   5. getFunction(String libraryName, String functionName, int, String) -> resolvable
     */
    private static FuncInfo classifyFunctionGetFunction(AbstractInvokeExpr inv,
                                                        Map<Local, String> localToString) {
        MethodSignature sig = inv.getMethodSignature();
        List<?> paramTypes = sig.getSubSignature().getParameterTypes();
        int paramCount = paramTypes.size();

        if (paramCount == 0) {
            return new FuncInfo("<?>", "<?>", API_UNKNOWN);
        }

        String firstParamType = paramTypes.get(0).toString();

        if ("java.lang.String".equals(firstParamType)) {
            String lib = resolveStringArg(inv, localToString, 0);
            String sym = resolveStringArg(inv, localToString, 1);

            String api;
            switch (paramCount) {
                case 2:  api = API_FN_GETFUNCTION_STR_STR;         break;
                case 3:  api = API_FN_GETFUNCTION_STR_STR_INT;     break;
                case 4:  api = API_FN_GETFUNCTION_STR_STR_INT_STR; break;
                default: api = API_UNKNOWN;                        break;
            }
            return new FuncInfo(lib, sym, api);
        }

        if (firstParamType.contains("Pointer")) {
            String api = (paramCount == 1) ? API_FN_GETFUNCTION_PTR : API_FN_GETFUNCTION_PTR_INT;
            return new FuncInfo("<?>", "<?>", api);
        }

        return new FuncInfo("<?>", "<?>", API_UNKNOWN);
    }

    // ----------------- Helper summaries (PASS 1) -----------------

    /**
     * If the method always boils down to returning a single constant String,
     * returns it; otherwise null. First resolvable return wins (accepted
     * imprecision for multi-return methods).
     */
    private String summarizeStringReturn(SootMethod m) {
        Map<Local, String> localToString = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                if (lhs instanceof Local) {
                    Local l = (Local) lhs;
                    String newString = null;
                    if (rhs instanceof StringConstant) {
                        newString = ((StringConstant) rhs).getValue();
                    } else if (rhs instanceof Local) {
                        newString = localToString.get(rhs);
                    } else if (rhs instanceof AbstractInvokeExpr) {
                        newString = methodStringReturns.get(
                                ((AbstractInvokeExpr) rhs).getMethodSignature().toString());
                    }
                    localToString.remove(l);
                    if (newString != null) localToString.put(l, newString);
                }
            } else if (stmt instanceof JReturnStmt) {
                Value ret = unwrapCasts(((JReturnStmt) stmt).getOp());
                if (ret instanceof StringConstant) {
                    return ((StringConstant) ret).getValue();
                }
                if (ret instanceof Local) {
                    String s = localToString.get(ret);
                    if (s != null) return s;
                }
            }
        }
        return null;
    }

    /**
     * Summarizes helpers returning a JNA Function, e.g.:
     *   private static Function lookup(String n) { return LIB.getFunction(n); }
     * The summary may defer to the call site (symbol from an argument) or to
     * the global field map (library from a field) via {@link FuncSummary}.
     */
    private FuncSummary summarizeFunctionReturn(SootMethod m) {
        Map<Local, String> nlToLib = new HashMap<>();
        Map<Local, String> nlToLibField = new HashMap<>();
        Map<Local, FuncSummary> fnToInfo = new HashMap<>();
        Map<Local, String> localToString = new HashMap<>();
        Map<Local, Integer> paramLocals = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            trackParameterLocal(stmt, paramLocals);

            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    localToString.put((Local) lhs, ((StringConstant) rhs).getValue());
                }

                if (lhs instanceof Local && rhs instanceof Local) {
                    Local l = (Local) lhs;
                    Local r = (Local) rhs;
                    if (nlToLib.containsKey(r)) nlToLib.put(l, nlToLib.get(r));
                    if (nlToLibField.containsKey(r)) nlToLibField.put(l, nlToLibField.get(r));
                    if (fnToInfo.containsKey(r)) fnToInfo.put(l, fnToInfo.get(r));
                    if (localToString.containsKey(r)) localToString.put(l, localToString.get(r));
                    if (paramLocals.containsKey(r)) paramLocals.put(l, paramLocals.get(r));
                }

                if (lhs instanceof Local && rhs instanceof JFieldRef) {
                    String fkey = fieldKey((JFieldRef) rhs);
                    String lib = fieldToLib.get(fkey);
                    if (lib != null) nlToLib.put((Local) lhs, lib);
                    else nlToLibField.put((Local) lhs, fkey);
                    FuncInfo fi = fieldToFunc.get(fkey);
                    if (fi != null) {
                        fnToInfo.put((Local) lhs, FuncSummary.fixed(fi));
                    }
                }

                if (lhs instanceof Local) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().getFullyQualifiedName();
                        String name = sig.getName();

                        if (JNA_NATIVE_LIBRARY.equals(decl) && "getInstance".equals(name)) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) nlToLib.put((Local) lhs, lib);
                        }

                        if (JNA_NATIVE_LIBRARY.equals(decl) && "getFunction".equals(name)) {
                            String lib = resolveLibFromInvokeBase(inv, nlToLib);
                            String libField = resolveLibFieldFromInvokeBase(inv, nlToLibField);
                            String sym = resolveStringArg(inv, localToString, 0);
                            Integer symParam = resolveParamArg(inv, paramLocals, 0);
                            if (sym == null && symParam == null && hasSingleStringParam(m)) {
                                symParam = 0;
                            }
                            fnToInfo.put((Local) lhs,
                                    new FuncSummary(lib, libField, sym, symParam, API_NATIVELIB_GETFUNCTION));
                        }

                        if (JNA_FUNCTION.equals(decl) && "getFunction".equals(name)) {
                            fnToInfo.put((Local) lhs,
                                    FuncSummary.fixed(classifyFunctionGetFunction(inv, localToString)));
                        }
                    }
                }
            } else if (stmt instanceof JReturnStmt) {
                Value ret = unwrapCasts(((JReturnStmt) stmt).getOp());
                if (ret instanceof Local) {
                    FuncSummary fs = fnToInfo.get(ret);
                    if (fs != null) return fs;
                }
            }
        }
        return null;
    }

    /**
     * Summarizes helpers returning a NativeLibrary with a constant library name.
     */
    private String summarizeNativeLibraryReturn(SootMethod m) {
        Map<Local, String> nlToLib = new HashMap<>();
        Map<Local, String> localToString = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    localToString.put((Local) lhs, ((StringConstant) rhs).getValue());
                }

                if (lhs instanceof Local && rhs instanceof Local) {
                    Local r = (Local) rhs;
                    if (nlToLib.containsKey(r)) nlToLib.put((Local) lhs, nlToLib.get(r));
                    if (localToString.containsKey(r)) localToString.put((Local) lhs, localToString.get(r));
                }

                if (lhs instanceof Local && rhs instanceof JFieldRef) {
                    String lib = fieldToLib.get(fieldKey((JFieldRef) rhs));
                    if (lib != null) nlToLib.put((Local) lhs, lib);
                }

                if (lhs instanceof Local) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        if (JNA_NATIVE_LIBRARY.equals(sig.getDeclClassType().getFullyQualifiedName())
                                && "getInstance".equals(sig.getName())) {
                            String lib = resolveStringArg(inv, localToString, 0);
                            if (lib != null) nlToLib.put((Local) lhs, lib);
                        }
                    }
                }
            } else if (stmt instanceof JReturnStmt) {
                Value ret = unwrapCasts(((JReturnStmt) stmt).getOp());
                if (ret instanceof Local) {
                    String lib = nlToLib.get(ret);
                    if (lib != null) return lib;
                }
                if (ret instanceof JFieldRef) {
                    String lib = fieldToLib.get(fieldKey((JFieldRef) ret));
                    if (lib != null) return lib;
                }
            }
        }
        return null;
    }

    /**
     * Records "local := @parameterN" identity statements using the proper
     * Jimple types (JIdentityStmt/JParameterRef) — no toString() parsing.
     */
    private static void trackParameterLocal(Stmt stmt, Map<Local, Integer> paramLocals) {
        if (!(stmt instanceof JIdentityStmt)) return;
        JIdentityStmt id = (JIdentityStmt) stmt;
        if (id.getRightOp() instanceof JParameterRef) {
            paramLocals.put(id.getLeftOp(), ((JParameterRef) id.getRightOp()).getIndex());
        }
    }

    private static Integer resolveParamArg(AbstractInvokeExpr inv, Map<Local, Integer> paramLocals, int argIndex) {
        List<Immediate> args = inv.getArgs();
        if (args.size() <= argIndex) return null;
        Immediate arg = args.get(argIndex);
        if (arg instanceof Local) return paramLocals.get(arg);
        return null;
    }

    private static boolean hasSingleStringParam(SootMethod m) {
        List<?> params = m.getSignature().getSubSignature().getParameterTypes();
        return params.size() == 1 && "java.lang.String".equals(params.get(0).toString());
    }

    private static String resolveLibFieldFromInvokeBase(AbstractInvokeExpr inv, Map<Local, String> nlToLibField) {
        Local base = getInvokeBaseLocal(inv);
        if (base != null) {
            String fkey = nlToLibField.get(base);
            if (fkey != null) return fkey;
        }

        return inv.getUses()
                .filter(v -> v instanceof JFieldRef)
                .map(v -> fieldKey((JFieldRef) v))
                .findFirst()
                .orElse(null);
    }

    // ----------------- Data classes -----------------

    /** Library + symbol resolved for a JNA Function object. */
    private static final class FuncInfo {
        final String lib;
        final String sym;
        final String apiPattern;

        FuncInfo(String lib, String sym, String apiPattern) {
            this.lib = lib;
            this.sym = sym;
            this.apiPattern = apiPattern;
        }
    }

    /**
     * Summary of a helper method returning a Function. Parts may be deferred:
     * the symbol to a call-site argument (symArgIndex), the library to a field
     * (libFieldKey, resolved against the field map at instantiation time).
     */
    private static final class FuncSummary {
        final String lib;
        final String libFieldKey;
        final String sym;
        final Integer symArgIndex;
        final String apiPattern;

        FuncSummary(String lib, String libFieldKey, String sym, Integer symArgIndex, String apiPattern) {
            this.lib = lib;
            this.libFieldKey = libFieldKey;
            this.sym = sym;
            this.symArgIndex = symArgIndex;
            this.apiPattern = apiPattern;
        }

        static FuncSummary fixed(FuncInfo fi) {
            return new FuncSummary(fi.lib, null, fi.sym, null, fi.apiPattern);
        }

        FuncInfo instantiate(AbstractInvokeExpr inv, Map<Local, String> localToString,
                             Map<String, String> fieldToLib) {
            String resolvedLib = lib;
            if (resolvedLib == null && libFieldKey != null) {
                resolvedLib = fieldToLib.get(libFieldKey);
            }
            String resolvedSym = sym;
            if (resolvedSym == null && symArgIndex != null) {
                resolvedSym = resolveStringArg(inv, localToString, symArgIndex);
            }
            return new FuncInfo(resolvedLib, resolvedSym, apiPattern);
        }
    }

    /** A detected Function.invoke* call. */
    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String apiPattern;
        final String sinkSig;
        final String stmt;

        Hit(String callerSig, String lib, String symbol, String apiPattern, String sinkSig, String stmt) {
            this.callerSig = callerSig;
            this.lib = lib;
            this.symbol = symbol;
            this.apiPattern = apiPattern;
            this.sinkSig = sinkSig;
            this.stmt = stmt;
        }
    }

}
