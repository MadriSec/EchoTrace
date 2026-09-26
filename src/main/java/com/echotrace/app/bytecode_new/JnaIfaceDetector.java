package com.echotrace.app.bytecode_new;

import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.NullConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.views.View;
import sootup.java.core.views.JavaView;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;

import static com.echotrace.app.bytecode_new.DetectorSupport.*;

/**
 * JNA Interface Mapping Detector (Target-only analysis)
 *
 * Detects JNA interface-based native calls:
 *   interface CLib extends Library { int strlen(String s); }
 *   CLib.INSTANCE.strlen("hello")  ->  lib="c", symbol="strlen"
 *
 * The library name comes from Native.load("c", CLib.class).
 * The symbol name is the method name itself (JNA convention).
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaIfaceDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]" \
 *     [-Ddetector.runtime.dir=<extra-classpath-dir>] [-Ddetector.debug=true]
 *
 * Outputs:
 *   - jna_iface_hits.txt   (interface method calls with lib/symbol/jar)
 *   - skipped_methods.txt  (methods that failed analysis)
 */
public final class JnaIfaceDetector {

    private static final String JNA_NATIVE  = "com.sun.jna.Native";
    private static final String JNA_LIBRARY = "com.sun.jna.Library";

    private static final Set<String> LOAD_METHODS =
            new HashSet<>(Arrays.asList("load", "loadLibrary"));
    private static final Set<String> WRAPPER_METHODS =
            Collections.singleton("synchronizedLibrary");

    private static final String API_NATIVE_LOAD_STR_CLASS        = "Native.load(String,Class)";
    private static final String API_NATIVE_LOAD_CLASS            = "Native.load(Class)";
    private static final String API_NATIVE_LOAD_CLASS_MAP        = "Native.load(Class,Map)";
    private static final String API_NATIVE_LOAD_NULL             = "Native.load(null,Class)";
    private static final String API_NATIVE_LOADLIBRARY_STR_CLASS = "Native.loadLibrary(String,Class)";
    private static final String API_NATIVE_LOADLIBRARY_CLASS     = "Native.loadLibrary(Class)";
    private static final String API_UNKNOWN                      = "<?>";

    // Platform-specific packages/libraries to exclude (not relevant in Linux containers)
    private static final Set<String> EXCLUDED_PLATFORMS = new HashSet<>(Arrays.asList(
        "com.sun.jna.platform.win32",
        "com.sun.jna.platform.WindowUtils",
        "com.sun.jna.platform.mac",
        "com.sun.jna.platform.unix.solaris"
    ));

    private static final Set<String> EXCLUDED_LIBS = new HashSet<>(Arrays.asList(
        "kernel32", "user32", "advapi32", "ole32", "shell32", "ntdll", "msvcrt",
        "CoreFoundation", "IOKit", "SystemB", "libpthread.dylib",
        "kstat2", "X11"
    ));

    private static final Set<String> EXCLUDED_CLASS_FRAGMENTS = new HashSet<>(Arrays.asList(
        "WindowsJNAAffinity", "OSXJNAAffinity", "SolarisJNAAffinity",
        "X11KeyboardUtils"
    ));

    // Progress logging intervals
    private static final int  METHOD_TICK  = 50_000;

    /** Max fixed-point iterations for the taint-population pass. */
    private static final int MAX_TAINT_ITERATIONS = 4;

    // Instance state (no mutable statics: reusable, testable, no cross-run leakage).

    /** field signature -> LoadInfo (persists across methods for <clinit> -> usage pattern) */
    private final Map<String, LoadInfo> fieldTaint = new HashMap<>();
    /** field signature -> possible constant String values (handles conditional assignment) */
    private final Map<String, Set<String>> fieldStringValues = new HashMap<>();
    /** synthetic accessor (access$NNN) -> field signature it returns */
    private final Map<String, String> accessorToField = new HashMap<>();
    /** helper method signature -> LoadInfo it returns (e.g. loadCLib()) */
    private final Map<String, LoadInfo> methodLoadReturns = new HashMap<>();
    /** memoized "does this interface extend com.sun.jna.Library" answers */
    private final Map<ClassType, Boolean> jnaLibraryCache = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnaIfaceDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : deriveDefaultOutDir(targetDir);

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        new JnaIfaceDetector().run(AnalysisContext.build(targetDir), out);
    }

    /** Runs over a shared, pre-parsed context (standalone main builds its own). */
    void run(AnalysisContext ctx, File out) throws IOException {
        File hitsFile = new File(out, "jna_iface_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        JavaView view = ctx.view; // needed for the Library-interface hierarchy check
        Map<String, String> nativeLibraryNames = ctx.nativeLibraryNames;
        Map<String, String> classToJar = ctx.classToJarScan;
        List<SootClass> targetClasses = ctx.targetClassesScan; // already outer-first
        System.out.println("[IFACE] classes=" + targetClasses.size() + " out=" + out.getAbsolutePath());

        try (
                BufferedWriter hitW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== JNA Interface Mapping Hits ===\n");
            hitW.write("Format: callerSig | lib | symbol | apiPattern | interface | calleeSig | callerJar | calleeJar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            final long start = System.currentTimeMillis();

            long methodsSeen = 0;
            long methodsScanned = 0;
            long hits = 0;
            long skipped = 0;

            // ============================================================
            // PRE-SCAN (diagnostic): brute-force check for ANY Native.load /
            // Native.loadLibrary calls, BEFORE taint analysis. Confirms whether
            // calls exist at all when downstream passes report zero hits.
            // ============================================================
            System.out.println("[PRE-SCAN] Searching for Native.load / Native.loadLibrary calls...");
            int preHitCount = 0;
            for (SootClass sc : targetClasses) {
                for (SootMethod sm : sc.getMethods()) {
                    try {
                        if (!sm.hasBody()) continue;
                        for (Stmt s : sm.getBody().getStmts()) {
                            AbstractInvokeExpr inv = getInvoke(s);
                            if (inv == null) continue;
                            MethodSignature calleeSig = inv.getMethodSignature();
                            if (JNA_NATIVE.equals(calleeSig.getDeclClassType().getFullyQualifiedName())
                                    && LOAD_METHODS.contains(calleeSig.getName())) {
                                preHitCount++;
                                StringBuilder argStr = new StringBuilder();
                                for (Immediate arg : inv.getArgs()) {
                                    if (argStr.length() > 0) argStr.append(", ");
                                    argStr.append(arg.getClass().getSimpleName()).append("=").append(arg);
                                }
                                System.out.println("[PRE-SCAN]   " + sm.getSignature()
                                        + " -> " + calleeSig.getDeclClassType().getFullyQualifiedName()
                                        + "." + calleeSig.getName() + "(" + argStr + ")");
                            }
                        }
                    } catch (VerifyError | Exception e) {
                        if (DEBUG) System.out.println("[DBG] PRE-SCAN skip " + sm.getSignature() + ": " + e);
                    }
                }
            }
            System.out.println("[PRE-SCAN] Found " + preHitCount + " raw Native.load/loadLibrary call(s)");
            System.out.println();

            // ============================================================
            // PASS 1 (fixed point): populate taints from ALL method bodies,
            // not just <clinit> — INSTANCE fields are also assigned in
            // constructors, init()/getInstance() helpers, etc.
            // Each iteration refreshes, in order:
            //   a) accessor summaries (access$NNN -> field)
            //   b) Native.load helper summaries (loadCLib() -> LoadInfo)
            //   c) field taints / field string values
            // Iterated because (b) can depend on (c) and vice versa.
            // ============================================================
            System.out.println("[PASS 1] Populating taints (fixed point, max "
                    + MAX_TAINT_ITERATIONS + " iterations)...");

            for (int iter = 0; iter < MAX_TAINT_ITERATIONS; iter++) {
                int prevAccessors = accessorToField.size();
                int prevSummaries = methodLoadReturns.size();
                int prevTaints    = fieldTaint.size();
                int prevStrings   = fieldStringValues.size();

                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        try {
                            if (!m.hasBody()) continue;

                            // (a) synthetic accessors
                            if (m.getName().startsWith("access$")) {
                                trackAccessorMethod(m);
                            }

                            // (b) helpers returning a loaded Library
                            String sig = m.getSignature().toString();
                            if (!methodLoadReturns.containsKey(sig)) {
                                LoadInfo li = summarizeLoadReturn(m);
                                if (li != null) methodLoadReturns.put(sig, li);
                            }

                            // (c) field taint population (no hit collection)
                            analyzeMethod(view, m, false, null, null);
                        } catch (VerifyError | RuntimeException e) {
                            if (iter == 0) {
                                skipped++;
                                writeSkip(skipW, m.getSignature().toString(), e);
                            }
                        }
                    }
                }

                System.out.println("[PASS 1." + iter + "] accessors=" + accessorToField.size()
                        + " loadSummaries=" + methodLoadReturns.size()
                        + " fieldTaints=" + fieldTaint.size()
                        + " fieldStrings=" + fieldStringValues.size());

                boolean stable = accessorToField.size() == prevAccessors
                        && methodLoadReturns.size() == prevSummaries
                        && fieldTaint.size() == prevTaints
                        && fieldStringValues.size() == prevStrings;
                if (stable && iter > 0) break;
            }

            // ============================================================
            // PASS 2: Process all methods and collect hits
            // ============================================================
            System.out.println("[PASS 2] Processing all methods for JNA interface calls...");
            Set<String> seenHits = new HashSet<>();  // Dedup: callerSig|lib|symbol|iface
            for (SootClass sc : targetClasses) {
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

                        String callerClass = sc.getType().getFullyQualifiedName();
                        String jarFile = classToJar.getOrDefault(callerClass, "<unknown>");

                        List<Hit> found = analyzeMethod(view, m, true, jarFile, classToJar);
                        for (Hit h : found) {
                            if (isPlatformExcluded(h)) continue;
                            // Include lib in the key: the same call site resolved
                            // to different libraries must NOT collapse to one row.
                            String dedupKey = h.callerSig + "|" + h.lib + "|" + h.symbol + "|" + h.iface;
                            if (!seenHits.add(dedupKey)) continue;
                            hits++;
                            hitW.write(h.callerSig + " | "
                                    + NativeLibraryNames.resolve(h.lib, nativeLibraryNames) + " | "
                                    + h.symbol + " | "
                                    + h.apiPattern + " | "
                                    + h.iface + " | "
                                    + h.calleeSig + " | "
                                    + h.callerJar + " | "
                                    + h.calleeJar + "\n");
                        }
                    } catch (VerifyError | RuntimeException e) {
                        // IOException from hitW.write deliberately propagates: a
                        // broken output file should abort the run, not be "skipped".
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }
            }

            System.out.println("[INFO] total JNA interface hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Returns true if the hit belongs to a non-Linux platform (Windows, Mac,
     * Solaris, X11) and should be excluded from the output.
     */
    private static boolean isPlatformExcluded(Hit h) {
        for (String excluded : EXCLUDED_PLATFORMS) {
            if (h.iface.startsWith(excluded) || h.callerSig.contains(excluded)) {
                return true;
            }
        }
        if (EXCLUDED_LIBS.contains(h.lib)) {
            return true;
        }
        for (String fragment : EXCLUDED_CLASS_FRAGMENTS) {
            if (h.callerSig.contains(fragment)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Analyzes a single method.
     *
     * Performs intra-procedural taint tracking to resolve library names for
     * calls to interfaces that extend com.sun.jna.Library. Tracks:
     * - Native.load("lib", Interface.class) calls mapping locals/fields to LoadInfo
     * - Native.synchronizedLibrary() wrapper calls
     * - String constants for conditional library name assignments
     * - Local-to-local and local-to-field propagation
     * - Accessor method (access$NNN) return values
     *
     * Note: statements are visited in list order; values assigned in different
     * branches accumulate (string sets) or last-write-wins (LoadInfo). This is
     * a deliberate, branch-insensitive over-approximation.
     *
     * @param view        SootUp view for type resolution
     * @param m           method to analyze
     * @param collectHits false during taint population (PASS 1), true in PASS 2
     * @param callerJar   jar containing the caller (PASS 2 only)
     * @param classToJar  class -> jar map for callee lookup (PASS 2 only)
     * @return list of hits (empty during PASS 1)
     */
    private List<Hit> analyzeMethod(View view, SootMethod m, boolean collectHits,
                                    String callerJar, Map<String, String> classToJar) {
        Map<Local, LoadInfo> localTaint = new HashMap<>();
        Map<Local, Set<String>> localStringValues = new HashMap<>();
        List<Hit> hits = collectHits ? new ArrayList<>() : Collections.emptyList();

        for (Stmt stmt : m.getBody().getStmts()) {

            // --- Handle assignments (taint tracking) ---
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                // local = StringConstant (accumulate: conditional branches assign
                // different constants to the same local)
                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    String strVal = ((StringConstant) rhs).getValue();
                    localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).add(strVal);
                    if (DEBUG) System.out.println("[DBG] STRING local: " + lhs + " = \"" + strVal + "\"");
                }

                // local = local (propagate string values and LoadInfo)
                if (lhs instanceof Local && rhs instanceof Local) {
                    LoadInfo li = localTaint.get(rhs);
                    if (li != null) localTaint.put((Local) lhs, li);

                    Set<String> strs = localStringValues.get(rhs);
                    if (strs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(strs);
                    }
                }

                // local = fieldref (getstatic/getfield)
                if (lhs instanceof Local && rhs instanceof JFieldRef) {
                    String fk = fieldKey((JFieldRef) rhs);
                    LoadInfo li = fieldTaint.get(fk);
                    if (li != null) localTaint.put((Local) lhs, li);

                    Set<String> fieldStrs = fieldStringValues.get(fk);
                    if (fieldStrs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(fieldStrs);
                    }
                }

                // local = invoke (Native.load / wrapper / helper / accessor)
                if (lhs instanceof Local) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        LoadInfo li = parseIfLoadOrWrapper(inv, localTaint, localStringValues);
                        if (li != null) {
                            localTaint.put((Local) lhs, li);
                            if (DEBUG) System.out.println("[DBG] TAINT local: " + lhs + " -> " + li.libName);
                        }

                        // Accessor method returning a string field?
                        String accessorField = accessorToField.get(methodKey(inv.getMethodSignature()));
                        if (accessorField != null) {
                            Set<String> fieldStrs = fieldStringValues.get(accessorField);
                            if (fieldStrs != null) {
                                localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(fieldStrs);
                                if (DEBUG) {
                                    System.out.println("[DBG] ACCESSOR: " + inv.getMethodSignature().getName()
                                            + " returns " + accessorField + " -> " + fieldStrs);
                                }
                            }
                        }
                    }
                }

                // fieldref = local (putstatic/putfield)
                if (lhs instanceof JFieldRef && rhs instanceof Local) {
                    String fk = fieldKey((JFieldRef) lhs);
                    LoadInfo li = localTaint.get(rhs);
                    if (li != null) {
                        fieldTaint.put(fk, li);
                        if (DEBUG) System.out.println("[DBG] TAINT field: " + fk + " -> " + li.libName);
                    }

                    Set<String> strs = localStringValues.get(rhs);
                    if (strs != null && !strs.isEmpty()) {
                        fieldStringValues.computeIfAbsent(fk, k -> new HashSet<>()).addAll(strs);
                        if (DEBUG) System.out.println("[DBG] STRING field: " + fk + " <- " + strs);
                    }
                }

                // fieldref = StringConstant (direct assignment)
                if (lhs instanceof JFieldRef && rhs instanceof StringConstant) {
                    String fk = fieldKey((JFieldRef) lhs);
                    String strVal = ((StringConstant) rhs).getValue();
                    fieldStringValues.computeIfAbsent(fk, k -> new HashSet<>()).add(strVal);
                    if (DEBUG) System.out.println("[DBG] STRING field direct: " + fk + " = \"" + strVal + "\"");
                }

                // fieldref = invoke (direct: INSTANCE = Native.load(...))
                if (lhs instanceof JFieldRef) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        LoadInfo li = parseIfLoadOrWrapper(inv, localTaint, localStringValues);
                        if (li != null) {
                            String fk = fieldKey((JFieldRef) lhs);
                            fieldTaint.put(fk, li);
                            if (DEBUG) System.out.println("[DBG] TAINT field from load: " + fk + " -> " + li.libName);
                        }
                    }
                }
            }

            // Skip hit collection during taint population
            if (!collectHits) continue;

            // --- Handle invoke: detect calls to JNA Library interfaces ---
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature callee = inv.getMethodSignature();
            ClassType declType = callee.getDeclClassType();

            if (!extendsJnaLibrary(view, declType)) continue;

            // Find taint from receiver (local or field).
            // NOTE: this scans ALL uses (receiver + args); a tainted Library
            // passed as an argument can be (mis)attributed — accepted imprecision.
            LoadInfo li = findTaintFromUses(inv, localTaint);
            if (li == null) continue;

            String lib = (li.libName != null) ? li.libName : "<?>";
            String api = (li.apiPattern != null) ? li.apiPattern : API_UNKNOWN;

            String calleeClass = declType.getFullyQualifiedName();
            String calleeJar = (classToJar != null)
                    ? classToJar.getOrDefault(calleeClass, "<unknown>") : "<unknown>";

            hits.add(new Hit(
                    m.getSignature().toString(),
                    lib,
                    callee.getName(),
                    api,
                    calleeClass,
                    callee.toString(),
                    callerJar != null ? callerJar : "<unknown>",
                    calleeJar
            ));
        }

        return hits;
    }

    /**
     * Tracks synthetic accessor methods (access$NNN) that return a field,
     * mapping the accessor to the field signature so accessor call sites can
     * be resolved to the field's tracked string values. Uses proper Jimple
     * types (JReturnStmt/JFieldRef) — no toString() parsing.
     */
    private void trackAccessorMethod(SootMethod m) {
        String methodKey = methodKey(m.getSignature());
        if (accessorToField.containsKey(methodKey)) return;
        if (!m.hasBody()) return;

        Map<Local, String> localToField = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt assign = (JAssignStmt) stmt;
                Value lhs = assign.getLeftOp();
                Value rhs = unwrapCasts(assign.getRightOp());
                if (lhs instanceof Local && rhs instanceof JFieldRef) {
                    localToField.put((Local) lhs, fieldKey((JFieldRef) rhs));
                }
            } else if (stmt instanceof JReturnStmt) {
                Value op = unwrapCasts(((JReturnStmt) stmt).getOp());
                String fk = null;
                if (op instanceof JFieldRef) {
                    fk = fieldKey((JFieldRef) op);          // return <FieldRef>
                } else if (op instanceof Local) {
                    fk = localToField.get(op);              // return $local
                }
                if (fk != null) {
                    accessorToField.put(methodKey, fk);
                    if (DEBUG) System.out.println("[DBG] ACCESSOR TRACKED: " + methodKey + " -> " + fk);
                    return;
                }
            }
        }
    }

    /** Stable key for an invoked/declared method: declaringClass.name */
    private static String methodKey(MethodSignature sig) {
        return sig.getDeclClassType().getFullyQualifiedName() + "." + sig.getName();
    }

    // ------------------- Taint recovery from invoke uses -------------------

    /**
     * Finds LoadInfo taint from an invoke expression's uses (receiver/arguments).
     * Checks local variables first, then field references.
     */
    private LoadInfo findTaintFromUses(AbstractInvokeExpr inv, Map<Local, LoadInfo> localTaint) {
        Optional<LoadInfo> fromLocal = inv.getUses()
                .filter(v -> v instanceof Local)
                .map(localTaint::get)
                .filter(Objects::nonNull)
                .findFirst();
        if (fromLocal.isPresent()) return fromLocal.get();

        return inv.getUses()
                .filter(v -> v instanceof JFieldRef)
                .map(v -> fieldTaint.get(fieldKey((JFieldRef) v)))
                .filter(Objects::nonNull)
                .findFirst()
                .orElse(null);
    }

    // ------------------- Native.load parsing -------------------

    /**
     * Parses an invoke expression to check if it's a Native.load() / wrapper /
     * summarized helper call.
     *
     * Handles:
     * - Native.load("libname", Interface.class) - extracts library name
     * - Native.load(Interface.class) / load(Interface.class, Map) - current process
     * - Native.load(null, Interface.class) - default C library
     * - Native.loadLibrary(...) variants
     * - Native.synchronizedLibrary(lib) - propagates taint from argument
     * - previously summarized helpers (METHOD_LOAD_RETURNS)
     *
     * Library names held in locals are resolved through tracked string sets
     * (handles Platform.isWindows() ? "msvcrt" : "c").
     */
    private LoadInfo parseIfLoadOrWrapper(AbstractInvokeExpr inv, Map<Local, LoadInfo> localTaint,
                                          Map<Local, Set<String>> localStringValues) {
        MethodSignature sig = inv.getMethodSignature();
        String decl = sig.getDeclClassType().getFullyQualifiedName();
        String name = sig.getName();

        LoadInfo summarized = methodLoadReturns.get(sig.toString());
        if (summarized != null) {
            return summarized;
        }

        if (JNA_NATIVE.equals(decl) && LOAD_METHODS.contains(name)) {
            boolean isLoadLibrary = "loadLibrary".equals(name);
            List<Immediate> args = inv.getArgs();

            if (!args.isEmpty()) {
                Immediate arg0 = args.get(0);

                // Native.load(Class) / Native.load(Class, Map): no library name,
                // defaults to the current process.
                if ("java.lang.Class".equals(arg0.getType().toString())) {
                    String api = isLoadLibrary
                            ? API_NATIVE_LOADLIBRARY_CLASS
                            : (args.size() >= 2 ? API_NATIVE_LOAD_CLASS_MAP : API_NATIVE_LOAD_CLASS);
                    if (DEBUG) System.out.println("[DBG] " + api + " -> default C library");
                    return new LoadInfo("<null:default-c-lib>", api);
                }

                if (arg0 instanceof StringConstant) {
                    return new LoadInfo(((StringConstant) arg0).getValue(),
                            isLoadLibrary ? API_NATIVE_LOADLIBRARY_STR_CLASS : API_NATIVE_LOAD_STR_CLASS);
                }
                if (arg0 instanceof NullConstant) {
                    if (DEBUG) System.out.println("[DBG] Native.load with null -> default C library");
                    return new LoadInfo("<null:default-c-lib>", API_NATIVE_LOAD_NULL);
                }
                if (arg0 instanceof Local) {
                    String lib = null;
                    Set<String> possibleLibs = localStringValues.get(arg0);
                    if (possibleLibs != null && !possibleLibs.isEmpty()) {
                        // Sorted for deterministic output across runs
                        lib = new TreeSet<>(possibleLibs).stream().collect(Collectors.joining("|"));
                    }
                    String api = isLoadLibrary ? API_NATIVE_LOADLIBRARY_STR_CLASS : API_NATIVE_LOAD_STR_CLASS;
                    if (DEBUG) System.out.println("[DBG] " + api + " with local -> resolved to: " + lib);
                    return new LoadInfo(lib, api);
                }
            }
            return new LoadInfo(null, API_UNKNOWN);
        }

        // Native.synchronizedLibrary(lib) - propagate taint (preserves inner apiPattern)
        if (JNA_NATIVE.equals(decl) && WRAPPER_METHODS.contains(name)) {
            List<Immediate> args = inv.getArgs();
            if (args.size() == 1 && args.get(0) instanceof Local) {
                return localTaint.get(args.get(0));
            }
        }

        return null;
    }

    /**
     * Summarizes helpers that return a JNA Library produced by
     * Native.load/loadLibrary or synchronizedLibrary, e.g.:
     *   private static CLib loadCLib() { return Native.load("c", CLib.class); }
     * Reads fieldTaint/fieldStringValues, so it benefits from PASS 1 iteration.
     */
    private LoadInfo summarizeLoadReturn(SootMethod m) {
        Map<Local, LoadInfo> localTaint = new HashMap<>();
        Map<Local, Set<String>> localStringValues = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = unwrapCasts(as.getRightOp());

                if (lhs instanceof Local && rhs instanceof StringConstant) {
                    localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>())
                            .add(((StringConstant) rhs).getValue());
                }

                if (lhs instanceof Local && rhs instanceof Local) {
                    LoadInfo li = localTaint.get(rhs);
                    if (li != null) localTaint.put((Local) lhs, li);
                    Set<String> strs = localStringValues.get(rhs);
                    if (strs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(strs);
                    }
                }

                if (lhs instanceof Local && rhs instanceof JFieldRef) {
                    String fk = fieldKey((JFieldRef) rhs);
                    LoadInfo li = fieldTaint.get(fk);
                    if (li != null) localTaint.put((Local) lhs, li);
                    Set<String> strs = fieldStringValues.get(fk);
                    if (strs != null) {
                        localStringValues.computeIfAbsent((Local) lhs, k -> new HashSet<>()).addAll(strs);
                    }
                }

                if (lhs instanceof Local) {
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        LoadInfo li = parseIfLoadOrWrapper(inv, localTaint, localStringValues);
                        if (li != null) localTaint.put((Local) lhs, li);
                    }
                }
            } else if (stmt instanceof JReturnStmt) {
                Value returned = unwrapCasts(((JReturnStmt) stmt).getOp());
                if (returned instanceof Local) {
                    LoadInfo li = localTaint.get(returned);
                    if (li != null) return li;
                } else if (returned instanceof JFieldRef) {
                    LoadInfo li = fieldTaint.get(fieldKey((JFieldRef) returned));
                    if (li != null) return li;
                }
            }
        }
        return null;
    }

    // ------------------- Type/hierarchy check -------------------

    /**
     * Checks (with memoization) whether a type is an interface extending
     * com.sun.jna.Library via BFS over the superinterface hierarchy.
     *
     * If the type itself cannot be resolved (e.g. JNA absent from the analysis
     * classpath), returns true to allow detection — callers still require a
     * matching taint, which bounds false positives.
     */
    private boolean extendsJnaLibrary(View view, ClassType ifaceType) {
        Boolean cached = jnaLibraryCache.get(ifaceType);
        if (cached != null) return cached;
        boolean result = computeExtendsJnaLibrary(view, ifaceType);
        jnaLibraryCache.put(ifaceType, result);
        return result;
    }

    private static boolean computeExtendsJnaLibrary(View view, ClassType ifaceType) {
        Optional<? extends SootClass> scOpt = view.getClass(ifaceType);
        if (!scOpt.isPresent()) {
            return true; // unresolvable: allow, taint requirement bounds FPs
        }
        if (!scOpt.get().isInterface()) return false;

        Deque<ClassType> q = new ArrayDeque<>();
        Set<ClassType> seen = new HashSet<>();
        q.add(ifaceType);

        while (!q.isEmpty()) {
            ClassType cur = q.removeFirst();
            if (!seen.add(cur)) continue;

            if (JNA_LIBRARY.equals(cur.getFullyQualifiedName())) return true;

            Optional<? extends SootClass> curOpt = view.getClass(cur);
            if (!curOpt.isPresent()) continue;

            for (ClassType itf : curOpt.get().getInterfaces()) {
                q.addLast(itf);
            }
        }
        return false;
    }

    // ------------------- Data classes -------------------

    /** Library load information for a Native.load() (or equivalent) call. */
    private static final class LoadInfo {
        final String libName;
        final String apiPattern;

        LoadInfo(String libName, String apiPattern) {
            this.libName = libName;
            this.apiPattern = apiPattern;
        }
    }

    /** A detected call to a method on an interface extending com.sun.jna.Library. */
    private static final class Hit {
        final String callerSig;
        final String lib;
        final String symbol;
        final String apiPattern;
        final String iface;
        final String calleeSig;
        final String callerJar;
        final String calleeJar;

        Hit(String callerSig, String lib, String symbol, String apiPattern,
            String iface, String calleeSig, String callerJar, String calleeJar) {
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
