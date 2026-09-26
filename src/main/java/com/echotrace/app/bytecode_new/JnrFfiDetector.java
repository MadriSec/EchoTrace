package com.echotrace.app.bytecode_new;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.ClassType;
import sootup.core.views.View;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.io.*;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * jnr-ffi Native Binding Detector
 *
 * Detects native calls made via the jnr-ffi framework:
 *   - LibraryLoader.create(Interface.class).library("c").load()
 *   - Library.loadLibrary("c", Interface.class)
 *
 * Recovers (library, symbol) by:
 *   1. PASS 1: Scanning &lt;clinit&gt; for LibraryLoader / Library.loadLibrary calls
 *      to build interface -&gt; library mappings
 *   2. PASS 2: For each discovered interface, enumerating all declared methods
 *      (each method name maps 1:1 to a C function symbol)
 *
 * Usage:
 *   java -cp "target/classes:target/deps/*" \
 *     com.echotrace.app.bytecode_new.JnrFfiDetector &lt;target-jars-dir&gt; [outDir]
 *
 * Outputs:
 *   - jnr_ffi_hits.txt      (interface method declarations with lib/symbol/jar)
 *   - skipped_methods.txt    (methods that failed analysis)
 */
public class JnrFfiDetector {

    private static final boolean DEBUG = false;

    // jnr-ffi class names
    private static final String JNR_LIBRARY_LOADER = "jnr.ffi.LibraryLoader";
    private static final String JNR_LIBRARY        = "jnr.ffi.Library";

    // API pattern constants
    private static final String API_LOADER_LIBRARY_LOAD = "LibraryLoader.create().library().load()";
    private static final String API_LOADER_LOAD_STRING  = "LibraryLoader.create().load(String)";
    private static final String API_LIBRARY_LOAD        = "Library.loadLibrary(...)";
    private static final String API_UNKNOWN             = "<?>";

    // Progress logging

    // ---- Global taint maps (populated in PASS 1) ----

    // Interface FQCN -> set of library names
    private static final Map<String, Set<String>> IFACE_TO_LIBS = new LinkedHashMap<>();
    // Interface FQCN -> API pattern strings
    private static final Map<String, Set<String>> IFACE_TO_APIS = new HashMap<>();

    // Field-level taint (for loader proxies stored in static fields)
    // field key -> interface FQCN
    private static final Map<String, String> FIELD_TO_IFACE = new HashMap<>();
    // field key -> set of library names
    private static final Map<String, Set<String>> FIELD_TO_LIBS = new HashMap<>();
    // field key -> string value
    private static final Map<String, String> FIELD_TO_STRING = new HashMap<>();

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnrFfiDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir    = (args.length >= 2) ? args[1] : ".";

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        File hitsFile    = new File(out, "jnr_ffi_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Collect target jars. Framework/runtime jars stay on the analysis
        // classpath, but are not scanned as application targets.
        List<String> targetJars = collectJarPaths(targetDir);
        List<String> scanTargetJars = targetScanJars(targetJars);
        Map<String, String> nativeLibraryNames = NativeLibraryNames.fromTargetDir(targetDir);
        System.out.println("[INFO] target jars: " + targetJars.size());
        System.out.println("[INFO] target jars scanned: " + scanTargetJars.size());
        System.out.println("[INFO] framework/runtime jars excluded from target scan: "
                + (targetJars.size() - scanTargetJars.size()));

        // Index target classes
        Map<String, String> classToJar = collectClassNamesFromJars(scanTargetJars);
        Set<String> targetClassNames = classToJar.keySet();
        System.out.println("[INFO] target classes indexed: " + targetClassNames.size());

        List<String> analysisJars = analysisClasspathJars(targetJars);
        String cp = toClassPath(analysisJars);
        System.out.println("[INFO] scanning target classes for jnr-ffi bindings");
        System.out.println("       target=" + targetDir);
        System.out.println("       out   =" + out.getAbsolutePath());

        // Setup SootUp
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(cp));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());

        JavaView view = new JavaView(inputs);

        try (
                BufferedWriter hitW  = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== jnr-ffi Native Binding Hits ===\n");
            hitW.write("Format: interface | lib | symbol | apiPattern | jar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            long skipped = 0;

            // Collect target classes from the view
            List<SootClass> targetClasses = new ArrayList<>();
            for (Iterator<? extends SootClass> it = view.getClasses().iterator(); it.hasNext();) {
                SootClass sc = it.next();
                String fqcn = sc.getType().getFullyQualifiedName();
                if (targetClassNames.contains(fqcn)) {
                    targetClasses.add(sc);
                }
            }
            System.out.println("[INFO] collected " + targetClasses.size() + " target classes for analysis");

            // Sort: outer classes first, then inner classes
            targetClasses.sort((a, b) -> {
                String an = a.getType().getFullyQualifiedName();
                String bn = b.getType().getFullyQualifiedName();
                boolean aInner = an.contains("$");
                boolean bInner = bn.contains("$");
                if (aInner != bInner) return aInner ? 1 : -1;
                return an.compareTo(bn);
            });

            // ============================================================
            // PASS 1: Process <clinit> methods to find jnr-ffi load calls
            // Run twice for transitive dependencies
            // ============================================================
            for (int iter = 0; iter < 2; iter++) {
                System.out.println("[PASS 1] Iteration " + (iter + 1) + " - processing <clinit> methods...");
                int clinitCount = 0;
                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        if (!m.getName().equals("<clinit>")) continue;
                        try {
                            if (!m.hasBody()) continue;
                            analyzeClinitMethod(m);
                            clinitCount++;
                        } catch (LinkageError ignored) {
                        } catch (Exception ignored) {
                        }
                    }
                }
                System.out.println("[PASS 1] Iteration " + (iter + 1) + " processed " + clinitCount + " <clinit> methods");
            }

            System.out.println("[PASS 1] Discovered " + IFACE_TO_LIBS.size() + " interface-to-library mappings:");
            for (Map.Entry<String, Set<String>> entry : IFACE_TO_LIBS.entrySet()) {
                System.out.println("         " + entry.getKey() + " -> " + entry.getValue());
            }

            // ============================================================
            // PASS 2: Prefer actual call sites to loaded jnr-ffi interfaces.
            // Fall back to full interface enumeration only when an interface is
            // loaded but no call sites are visible in the analyzed bytecode.
            // ============================================================
            System.out.println("[PASS 2] Scanning call sites for discovered interfaces...");

            long hits = 0;
            Set<String> seenHitKeys = new LinkedHashSet<>();
            Set<String> interfacesWithCallsites = new HashSet<>();

            for (SootClass sc : targetClasses) {
                for (SootMethod m : sc.getMethods()) {
                    try {
                        if (!m.hasBody()) continue;
                        for (Stmt stmt : m.getBody().getStmts()) {
                            AbstractInvokeExpr inv = getInvoke(stmt);
                            if (inv == null) continue;

                            MethodSignature sig = inv.getMethodSignature();
                            String ifaceFqcn = sig.getDeclClassType().getFullyQualifiedName();
                            Set<String> libs = IFACE_TO_LIBS.get(ifaceFqcn);
                            if (libs == null) continue;

                            String methodName = sig.getName();
                            if ("<clinit>".equals(methodName) || "<init>".equals(methodName)) continue;

                            interfacesWithCallsites.add(ifaceFqcn);
                            String libStr = NativeLibraryNames.resolve(String.join("|", libs), nativeLibraryNames);
                            String api = apiString(ifaceFqcn);
                            String jar = classToJar.getOrDefault(ifaceFqcn, "?");
                            String key = ifaceFqcn + "|" + libStr + "|" + methodName;
                            if (!seenHitKeys.add(key)) continue;

                            hits++;
                            hitW.write(ifaceFqcn);
                            hitW.write(" | ");
                            hitW.write(libStr);
                            hitW.write(" | ");
                            hitW.write(methodName);
                            hitW.write(" | ");
                            hitW.write(api);
                            hitW.write(" | ");
                            hitW.write(jar);
                            hitW.write("\n");
                        }
                    } catch (LinkageError le) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), le);
                    } catch (Exception e) {
                        skipped++;
                        writeSkip(skipW, m.getSignature().toString(), e);
                    }
                }
            }

            System.out.println("[PASS 2] Callsite hits: " + hits);
            System.out.println("[PASS 3] Enumerating fallback interfaces with no call sites...");
            for (Map.Entry<String, Set<String>> entry : IFACE_TO_LIBS.entrySet()) {
                String ifaceFqcn = entry.getKey();
                if (interfacesWithCallsites.contains(ifaceFqcn)) continue;
                Set<String> libs = entry.getValue();
                String libStr = NativeLibraryNames.resolve(String.join("|", libs), nativeLibraryNames);
                String api = apiString(ifaceFqcn);
                String jar = classToJar.getOrDefault(ifaceFqcn, "?");

                // BFS to enumerate all methods in interface hierarchy
                Set<String> methodNames = enumerateInterfaceMethods(view, ifaceFqcn);

                if (DEBUG) {
                    System.out.println("[DBG] Interface " + ifaceFqcn + " has " + methodNames.size() + " methods");
                }

                for (String methodName : methodNames) {
                    String key = ifaceFqcn + "|" + libStr + "|" + methodName;
                    if (!seenHitKeys.add(key)) continue;
                    hits++;
                    hitW.write(ifaceFqcn);
                    hitW.write(" | ");
                    hitW.write(libStr);
                    hitW.write(" | ");
                    hitW.write(methodName);
                    hitW.write(" | ");
                    hitW.write(api);
                    hitW.write(" | ");
                    hitW.write(jar);
                    hitW.write("\n");
                }
                hitW.flush();
            }

            System.out.println("[INFO] total jnr-ffi hits: " + hits);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    // ---- PASS 1: <clinit> analysis ----

    /**
     * Analyzes a single &lt;clinit&gt; method for jnr-ffi library loading patterns.
     *
     * Tracks:
     * - LibraryLoader.create(Class) -> interface taint
     * - LibraryLoader.library(String) -> library name accumulation
     * - LibraryLoader.load() / load(String) -> commit interface-to-library mapping
     * - Library.loadLibrary(...) -> direct commit
     */
    private static void analyzeClinitMethod(SootMethod m) {
        // Per-method local taint maps
        Map<Local, String> localToString       = new HashMap<>();
        Map<Local, String> loaderToIface        = new HashMap<>();
        Map<Local, Set<String>> loaderToLibs    = new HashMap<>();
        Map<Local, String> loaderToApi          = new HashMap<>();

        String callerClass = m.getDeclaringClassType().getFullyQualifiedName();

        for (Stmt stmt : m.getBody().getStmts()) {

            // ---- JAssignStmt: local = ... or field = ... ----
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rawRhs = as.getRightOp();
                Value rhs = unwrapCasts(rawRhs);

                if (lhs instanceof Local) {
                    Local l = (Local) lhs;

                    // local = StringConstant
                    if (rhs instanceof StringConstant) {
                        localToString.put(l, ((StringConstant) rhs).getValue());
                    }

                    // local = invoke
                    AbstractInvokeExpr inv = asInvoke(rhs);
                    if (inv != null) {
                        MethodSignature sig = inv.getMethodSignature();
                        String decl = sig.getDeclClassType().getFullyQualifiedName();
                        String name = sig.getName();

                        // --- LibraryLoader.create(Class) ---
                        if (JNR_LIBRARY_LOADER.equals(decl) && "create".equals(name)) {
                            String iface = resolveClassArg(inv, 0);
                            // Fallback: use cast target from the raw rhs
                            if (iface == null) {
                                iface = extractCastTarget(rawRhs);
                            }
                            if (iface != null) {
                                loaderToIface.put(l, iface);
                                loaderToLibs.put(l, new LinkedHashSet<>());
                                loaderToApi.put(l, API_LOADER_LIBRARY_LOAD);
                                if (DEBUG) System.out.println("[DBG] create: iface=" + iface);
                            }
                        }

                        // --- LibraryLoader.library(String) ---
                        if (JNR_LIBRARY_LOADER.equals(decl) && "library".equals(name)) {
                            Local base = getInvokeBaseLocal(inv);
                            String libName = resolveStringArg(inv, localToString, 0);

                            // Add lib to the loader's accumulated libs
                            if (base != null && loaderToLibs.containsKey(base)) {
                                if (libName != null) {
                                    loaderToLibs.get(base).add(libName);
                                }
                                // Propagate loader taint to lhs (library() returns this)
                                propagateLoader(l, base, loaderToIface, loaderToLibs, loaderToApi);
                            }
                            if (DEBUG) System.out.println("[DBG] library: lib=" + libName);
                        }

                        // --- Builder chainers: searchDefault, failImmediately, option, search, mapper ---
                        if (JNR_LIBRARY_LOADER.equals(decl) && isBuilderChainer(name)) {
                            Local base = getInvokeBaseLocal(inv);
                            if (base != null && loaderToIface.containsKey(base)) {
                                propagateLoader(l, base, loaderToIface, loaderToLibs, loaderToApi);
                            }
                        }

                        // --- LibraryLoader.load() or load(String) ---
                        if (JNR_LIBRARY_LOADER.equals(decl) && "load".equals(name)) {
                            Local base = getInvokeBaseLocal(inv);
                            String iface = (base != null) ? loaderToIface.get(base) : null;
                            Set<String> libs = (base != null) ? loaderToLibs.get(base) : null;
                            String api = (base != null) ? loaderToApi.get(base) : null;

                            // load(String) overload: string arg IS the library name
                            List<Immediate> loadArgs = inv.getArgs();
                            if (!loadArgs.isEmpty()) {
                                String libArg = resolveStringArg(inv, localToString, 0);
                                if (libArg != null) {
                                    if (libs == null) libs = new LinkedHashSet<>();
                                    libs.add(libArg);
                                }
                                api = API_LOADER_LOAD_STRING;
                            }

                            // Fallback: if interface unknown, try cast target on the assignment
                            if (iface == null) {
                                iface = extractCastTarget(rawRhs);
                            }

                            commitIfaceLibs(iface, libs, api);
                            if (DEBUG) System.out.println("[DBG] load: iface=" + iface + " libs=" + libs);
                        }

                        // --- Library.loadLibrary(...) ---
                        if (JNR_LIBRARY.equals(decl) && "loadLibrary".equals(name)) {
                            handleStaticLoadLibrary(inv, localToString, rawRhs);
                        }
                    }

                    // local = local (propagation)
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (localToString.containsKey(r)) localToString.put(l, localToString.get(r));
                        if (loaderToIface.containsKey(r)) {
                            propagateLoader(l, r, loaderToIface, loaderToLibs, loaderToApi);
                        }
                    }

                    // local = getstatic/getfield (load taint from global maps)
                    if (isFieldRef(rhs)) {
                        String fkey = fieldKey(rhs);
                        if (FIELD_TO_STRING.containsKey(fkey)) {
                            localToString.put(l, FIELD_TO_STRING.get(fkey));
                        }
                    }
                }

                // ---- field = something (putstatic/putfield) ----
                if (isFieldRef(lhs)) {
                    String fkey = fieldKey(lhs);

                    // field = StringConstant
                    if (rhs instanceof StringConstant) {
                        FIELD_TO_STRING.put(fkey, ((StringConstant) rhs).getValue());
                    }

                    // field = local (propagate local taint to field)
                    if (rhs instanceof Local) {
                        Local r = (Local) rhs;
                        if (localToString.containsKey(r)) {
                            FIELD_TO_STRING.put(fkey, localToString.get(r));
                        }
                    }
                }
            }

            // ---- Standalone JInvokeStmt (return value discarded) ----
            if (stmt instanceof JInvokeStmt) {
                AbstractInvokeExpr inv = getInvoke(stmt);
                if (inv == null) continue;

                MethodSignature sig = inv.getMethodSignature();
                String decl = sig.getDeclClassType().getFullyQualifiedName();
                String name = sig.getName();

                // LibraryLoader.library(String) — standalone (pop'd return)
                if (JNR_LIBRARY_LOADER.equals(decl) && "library".equals(name)) {
                    Local base = getInvokeBaseLocal(inv);
                    String libName = resolveStringArg(inv, localToString, 0);

                    if (base != null && loaderToLibs.containsKey(base) && libName != null) {
                        loaderToLibs.get(base).add(libName);
                        if (DEBUG) System.out.println("[DBG] standalone library: lib=" + libName);
                    }
                }

                // Library.loadLibrary(...) — standalone
                if (JNR_LIBRARY.equals(decl) && "loadLibrary".equals(name)) {
                    handleStaticLoadLibrary(inv, localToString, null);
                }
            }
        }
    }

    /**
     * Handles Library.loadLibrary(...) static factory calls.
     *
     * Overloads:
     *   loadLibrary(String lib, Class iface)
     *   loadLibrary(Class iface, String... libs)
     *   loadLibrary(String lib, Class iface, Map options)
     *   loadLibrary(Class iface, Map options, String... libs)
     */
    private static void handleStaticLoadLibrary(AbstractInvokeExpr inv,
                                                 Map<Local, String> localToString,
                                                 Value rawRhs) {
        List<Immediate> args = inv.getArgs();
        if (args.isEmpty()) return;

        String iface = null;
        Set<String> libs = new LinkedHashSet<>();

        // Try to resolve each argument
        for (Immediate arg : args) {
            // Check if it's a Class constant
            String cls = resolveAsClassConstant(arg);
            if (cls != null && iface == null) {
                iface = cls;
                continue;
            }

            // Check if it's a String
            if (arg instanceof StringConstant) {
                libs.add(((StringConstant) arg).getValue());
            } else if (arg instanceof Local && localToString.containsKey((Local) arg)) {
                libs.add(localToString.get((Local) arg));
            }
        }

        // Fallback: cast target
        if (iface == null && rawRhs != null) {
            iface = extractCastTarget(rawRhs);
        }

        commitIfaceLibs(iface, libs, API_LIBRARY_LOAD);
        if (DEBUG) System.out.println("[DBG] Library.loadLibrary: iface=" + iface + " libs=" + libs);
    }

    /**
     * Commits a discovered interface-to-library mapping.
     */
    private static void commitIfaceLibs(String iface, Set<String> libs, String api) {
        if (iface == null) return;
        if (libs == null || libs.isEmpty()) {
            // Library name unresolvable but interface is known
            IFACE_TO_LIBS.computeIfAbsent(iface, k -> new LinkedHashSet<>()).add("<?>");
        } else {
            IFACE_TO_LIBS.computeIfAbsent(iface, k -> new LinkedHashSet<>()).addAll(libs);
        }
        if (api != null) {
            IFACE_TO_APIS.computeIfAbsent(iface, k -> new LinkedHashSet<>()).add(api);
        }
    }

    private static String apiString(String iface) {
        Set<String> apis = IFACE_TO_APIS.get(iface);
        if (apis == null || apis.isEmpty()) return API_UNKNOWN;
        return String.join("|", apis);
    }

    /**
     * Propagates loader taint from source local to destination local.
     */
    private static void propagateLoader(Local dst, Local src,
                                         Map<Local, String> loaderToIface,
                                         Map<Local, Set<String>> loaderToLibs,
                                         Map<Local, String> loaderToApi) {
        if (loaderToIface.containsKey(src)) loaderToIface.put(dst, loaderToIface.get(src));
        if (loaderToLibs.containsKey(src))  loaderToLibs.put(dst, loaderToLibs.get(src));
        if (loaderToApi.containsKey(src))   loaderToApi.put(dst, loaderToApi.get(src));
    }

    /**
     * Returns true for builder-chaining methods that return 'this' but don't carry
     * library or interface information.
     */
    private static boolean isBuilderChainer(String name) {
        switch (name) {
            case "searchDefault":
            case "failImmediately":
            case "option":
            case "search":
            case "mapper":
            case "convention":
            case "saveError":
                return true;
            default:
                return false;
        }
    }

    // ---- PASS 2: Interface method enumeration ----

    /**
     * BFS traversal of the interface hierarchy to enumerate all method names.
     * Each method name maps 1:1 to a C function symbol.
     * Overloaded methods (same name, different params) are deduplicated.
     */
    private static Set<String> enumerateInterfaceMethods(View view, String ifaceFqcn) {
        Set<String> methods = new LinkedHashSet<>();
        Set<String> visited = new HashSet<>();
        Deque<String> queue = new ArrayDeque<>();
        queue.add(ifaceFqcn);

        while (!queue.isEmpty()) {
            String current = queue.removeFirst();
            if (!visited.add(current)) continue;
            if ("java.lang.Object".equals(current)) continue;

            try {
                ClassType ct = view.getIdentifierFactory().getClassType(current);
                Optional<? extends SootClass> scOpt = view.getClass(ct);
                if (!scOpt.isPresent()) continue;

                SootClass sc = scOpt.get();

                // Collect non-static, non-special method names
                for (SootMethod sm : sc.getMethods()) {
                    String mName = sm.getName();
                    if ("<clinit>".equals(mName) || "<init>".equals(mName)) continue;
                    if (sm.isStatic()) continue;
                    methods.add(mName);
                }

                // Traverse super-interfaces
                for (ClassType superIface : sc.getInterfaces()) {
                    String superFqcn = superIface.getFullyQualifiedName();
                    if (!"java.lang.Object".equals(superFqcn)) {
                        queue.addLast(superFqcn);
                    }
                }
            } catch (Exception e) {
                if (DEBUG) System.err.println("[DBG] Failed to resolve interface: " + current + " :: " + e.getMessage());
            }
        }

        return methods;
    }

    // ---- Resolution helpers ----

    /**
     * Resolves a string argument from an invoke expression.
     */
    private static String resolveStringArg(AbstractInvokeExpr inv, Map<Local, String> localToString, int argIndex) {
        List<Immediate> args = inv.getArgs();
        if (args.size() <= argIndex) return null;

        Immediate arg = args.get(argIndex);
        if (arg instanceof StringConstant) {
            return ((StringConstant) arg).getValue();
        }
        if (arg instanceof Local) {
            return localToString.get((Local) arg);
        }
        return null;
    }

    /**
     * Resolves a Class argument from an invoke expression.
     * In bytecode, class literals (ldc Foo.class) appear as ClassConstant in SootUp.
     */
    private static String resolveClassArg(AbstractInvokeExpr inv, int argIndex) {
        List<Immediate> args = inv.getArgs();
        if (args.size() <= argIndex) return null;

        Immediate arg = args.get(argIndex);
        return resolveAsClassConstant(arg);
    }

    /**
     * Tries to resolve a value as a class constant.
     * Handles SootUp's ClassConstant representation.
     */
    private static String resolveAsClassConstant(Value v) {
        if (v == null) return null;

        String className = v.getClass().getName().toLowerCase(Locale.ROOT);
        if (className.contains("classconstant")) {
            // ClassConstant — extract FQCN
            // In SootUp, ClassConstant.getValue() returns something like "Ljnr/posix/LibC;"
            // or toString() returns the type info
            String repr = v.toString();
            return cleanClassConstant(repr);
        }
        return null;
    }

    /**
     * Cleans a ClassConstant representation to a FQCN.
     * Handles formats like:
     *   "class \"Ljnr/posix/LibC;\""  -> "jnr.posix.LibC"
     *   "class \"jnr/posix/LibC\""    -> "jnr.posix.LibC"
     *   "jnr.posix.LibC"              -> "jnr.posix.LibC"
     */
    private static String cleanClassConstant(String raw) {
        if (raw == null) return null;

        // Strip wrapping like: class "..."
        String s = raw.trim();
        if (s.startsWith("class ")) s = s.substring(6).trim();
        s = s.replace("\"", "");

        // Handle descriptor format: Ljnr/posix/LibC;
        if (s.startsWith("L") && s.endsWith(";")) {
            s = s.substring(1, s.length() - 1);
        }

        // Convert slashes to dots
        s = s.replace('/', '.');

        // Skip primitives and arrays
        if (s.isEmpty() || s.startsWith("[")) return null;

        return s;
    }

    /**
     * Extracts the cast target type from a Value that may be a cast expression.
     * Used as fallback when the Class argument to create() is unresolvable.
     *
     * In Jimple: (jnr.posix.LibC) virtualinvoke $r.load()
     * The cast target is jnr.posix.LibC.
     */
    private static String extractCastTarget(Value v) {
        if (v == null) return null;

        String cn = v.getClass().getName().toLowerCase(Locale.ROOT);
        if (!cn.contains("cast")) return null;

        // Try getType() to get the cast target type
        Object type = tryInvokeObj(v, "getType");
        if (type != null) {
            String typeStr = type.toString();
            // Skip java.lang.Object (too generic)
            if (!"java.lang.Object".equals(typeStr)) {
                return typeStr;
            }
        }

        return null;
    }

    // ---- Jimple helpers (copied from existing detectors) ----

    private static AbstractInvokeExpr asInvoke(Value v) {
        return (v instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) v : null;
    }

    private static AbstractInvokeExpr getInvoke(Stmt stmt) {
        if (stmt instanceof JInvokeStmt) {
            Object ie = ((JInvokeStmt) stmt).getInvokeExpr();
            if (ie instanceof AbstractInvokeExpr) return (AbstractInvokeExpr) ie;
            if (ie instanceof Optional) {
                Object val = ((Optional<?>) ie).orElse(null);
                return (val instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) val : null;
            }
        } else if (stmt instanceof JAssignStmt) {
            Value rhs = ((JAssignStmt) stmt).getRightOp();
            if (rhs instanceof AbstractInvokeExpr) return (AbstractInvokeExpr) rhs;
        }
        return null;
    }

    private static Local getInvokeBaseLocal(AbstractInvokeExpr inv) {
        Value base = tryInvokeValue(inv, "getBase");
        if (base instanceof Local) return (Local) base;

        Object baseBox = tryInvokeObj(inv, "getBaseBox");
        if (baseBox != null) {
            Object v = tryInvokeObj(baseBox, "getValue");
            if (v instanceof Local) return (Local) v;
        }

        return inv.getUses().filter(u -> u instanceof Local).map(u -> (Local) u).findFirst().orElse(null);
    }

    private static Value tryInvokeValue(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            Object r = m.invoke(target);
            return (r instanceof Value) ? (Value) r : null;
        } catch (Exception ignored) {
            return null;
        }
    }

    private static Object tryInvokeObj(Object target, String method) {
        try {
            Method m = target.getClass().getMethod(method);
            return m.invoke(target);
        } catch (Exception ignored) {
            return null;
        }
    }

    private static boolean isFieldRef(Value v) {
        if (v == null) return false;
        return v.getClass().getName().contains("FieldRef");
    }

    private static String fieldKey(Value fieldRef) {
        return fieldRef.toString();
    }

    private static Value unwrapCasts(Value v) {
        Value cur = v;
        for (int i = 0; i < 8 && cur != null; i++) {
            String cn = cur.getClass().getName().toLowerCase(Locale.ROOT);
            if (!cn.contains("cast")) break;

            Value inner = tryInvokeValue(cur, "getOp");
            if (inner == null) inner = tryInvokeValue(cur, "getOperand");
            if (inner == null) inner = tryInvokeValue(cur, "getValue");

            if (inner == null) break;
            cur = inner;
        }
        return cur;
    }

    private static void writeSkip(BufferedWriter w, String methodSig, Throwable t) throws IOException {
        String msg = (t.getMessage() == null) ? "" : t.getMessage().replace('\n', ' ').replace('\r', ' ');
        w.write(methodSig);
        w.write(" | ");
        w.write(t.getClass().getName());
        w.write(" | ");
        w.write(msg);
        w.write("\n");
    }

    // ---- Jar scanning helpers ----

    private static List<String> collectJarPaths(String dirPath) {
        List<String> jars = new ArrayList<>();
        File root = new File(dirPath);
        if (!root.exists() || !root.isDirectory()) {
            System.err.println("[ERROR] Invalid directory: " + dirPath);
            return jars;
        }

        Deque<File> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            File cur = stack.pop();
            File[] files = cur.listFiles();
            if (files == null) continue;
            for (File f : files) {
                if (f.isDirectory()) stack.push(f);
                else if (f.getName().endsWith(".jar")) jars.add(f.getAbsolutePath());
            }
        }

        Collections.sort(jars);
        return jars;
    }

    private static List<String> targetScanJars(List<String> jars) {
        return jars.stream()
                .filter(jar -> !isFrameworkRuntimeJar(jar))
                .collect(Collectors.toList());
    }

    private static boolean isFrameworkRuntimeJar(String jarPath) {
        String name = new File(jarPath).getName().toLowerCase(Locale.ROOT);
        return name.startsWith("jna-")
                || name.startsWith("jnr-")
                || name.startsWith("jffi-")
                || name.startsWith("hawtjni-runtime-");
    }

    private static Map<String, String> collectClassNamesFromJars(List<String> jarPaths) {
        Map<String, String> classToJar = new HashMap<>();
        for (String jar : jarPaths) {
            String jarName = new File(jar).getName();
            try (ZipFile zf = new ZipFile(jar)) {
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    String name = e.getName();
                    if (name.endsWith(".class") && !name.contains("module-info")) {
                        String cls = name.substring(0, name.length() - 6).replace('/', '.');
                        classToJar.put(cls, jarName);
                    }
                }
            } catch (Exception ex) {
                System.err.println("[WARN] failed reading jar: " + jar + " :: " + ex.getMessage());
            }
        }
        return classToJar;
    }

    private static String toClassPath(List<String> entries) {
        String sep = System.getProperty("path.separator");
        return entries.stream().collect(Collectors.joining(sep));
    }

    private static List<String> analysisClasspathJars(List<String> targetJars) {
        List<String> jars = new ArrayList<>(targetJars);
        String runtimeDir = System.getProperty("detector.runtime.dir");
        if (runtimeDir != null && !runtimeDir.trim().isEmpty()) {
            List<String> runtimeJars = collectJarPaths(runtimeDir.trim());
            jars.addAll(runtimeJars);
            System.out.println("[INFO] detector.runtime.dir jars: " + runtimeJars.size());
        }
        return jars;
    }
}
