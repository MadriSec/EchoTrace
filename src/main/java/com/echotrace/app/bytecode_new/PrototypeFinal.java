package com.echotrace.app.bytecode_new;
// sootup imports
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.core.signatures.MethodSignature;
import sootup.java.core.views.JavaView;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.model.Body;
import sootup.core.model.MethodModifier;

// ASM imports
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import java.io.*;
import java.util.*;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;
import java.util.jar.JarFile;
import java.util.jar.JarEntry;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.MalformedURLException;

/**
 * Native Method Tracer - ASM and SootUp Based Analysis
 *
 * This class provides comprehensive analysis of native method usage in Java applications.
 * It provides two analysis approaches: ASM-based bytecode analysis and SootUp-based
 * Jimple analysis to trace native method calls and their execution paths.
 *
 * USAGE:
 *   java PrototypeFinal <target-directory> [<dependencies-directory>] [--1|--2] [--runtime DIR ...]
 *
 * INPUT REQUIREMENTS:
 *   - target-directory: Directory containing application JAR files to analyze (Mode 1 scans this directory only)
 *   - dependencies-directory: Optional. Required for Mode 2 (--2): directory containing dependency JAR files.
 *     Ignored for Mode 1 (--1); put app JARs under target-directory and use --runtime for JDK/runtime flat JARs.
 *   - mode: Analysis mode selector (--1 or --2)
 *   - optional --runtime DIR: directory whose *.jar files are placed on the
 *     hermetic URLClassLoader only (for resolving invokes into the JDK). These
 *     JARs are NOT scanned in traceJarFiles, so e.g. java.base.jar does not
 *     dump every JDK native — only classes reached via invoke chains are read.
 *     Example: {@code --runtime RUNTIME_zookeeper_3.8/} (next token must be the path;
 *     do not insert the literal word {@code DIR}).
 *     Same effect as env {@code PROTOTYPE_RUNTIME_DIR} (single directory).
 *
 * ANALYSIS MODES:
 *   --1: Use HybridByteCodeTracer approach (ASM-based native method detection).
 *        Use case: Bytecode-level analysis using ASM framework
 *   --2 (default): SootUp Visitor Pattern (Worklist-based, using Jimple instead of ASM).
 *        Use case: Jimple-based analysis for finding all reachable native methods
 *
 * OUTPUT FILES (per-container):
 *   Mode 1: derived from target-directory (same JARFILES_/outputs_ convention as before).
 *   Mode 2: derived from dependencies-directory when present, otherwise target-directory.
 *           For input  JARFILES_<IMG_SAFE>(_with_jdk)?  results land in
 *              outputs_<IMG_SAFE>/native_methods.txt           (mode 1)
 *              outputs_<IMG_SAFE>/sootup_visitor_natives.txt   (mode 2)
 *   The output dir is created if missing.  Override with the system property
 *   -Dprototype.output.dir=<path> when running.
 */
public class PrototypeFinal {
    // Shared fields
    private static final Map<String, String> classToJar = new HashMap<>();
    private static Set<String> targetJarClasses = new HashSet<>();
    private static Set<String> dependencyClasses = new HashSet<>();

    // HybridByteCodeTracer fields (Mode 1)
    private static String pathPrefix = "JARFILES/";
    /**
     * Where Mode 1 writes its results.  Initialised to a CWD-relative fallback
     * overridden per-run to <project_root>/outputs_<IMG_SAFE>/native_methods.txt
     * by {@link #resolveOutputDir(String)} once the output anchor directory is known.
     */
    private static String NATIVE_METHODS_FILE = "native_methods.txt";
    private static URLClassLoader targetClassLoader = null;

    /**
     * Main entry point for the Native Method Tracer
     *
     * FUNCTION NAME: main
     *
     * USAGE:
     *   java PrototypeFinal <target-directory> [<dependencies-directory>] [--1|--2] [--runtime DIR ...]
     *
     * INPUT REQUIRED:
     *   - args[0]: target-directory - JARs to scan (Mode 1) or target JARs (Mode 2)
     *   - optional: dependencies-directory — first non-flag argument after target; required for Mode 2
     *   - flags: --1 (ASM), --2 (SootUp), --runtime DIR
     *
     * WHAT IT'S USED FOR:
     *   - Orchestrates the native method analysis workflow
     *   - Parses command line arguments and validates input
     *   - Selects appropriate analysis mode based on user input
     *   - Executes the chosen analysis strategy
     *   - Generates comprehensive output files with results
     *
     * PROCESS FLOW:
     *   1. Parse and validate command line arguments
     *   2. Determine analysis mode (--1 or --2)
     *   3. Execute mode-specific analysis logic
     *   4. Generate output files with results
     */
    public static void main(String[] args) {
        if (args.length < 1) {
            System.err.println("Usage: java PrototypeFinal <target-directory> [<dependencies-directory>] [--1|--2] [--runtime DIR ...]");
            System.err.println("  Mode 1 (--1): scans <target-directory> for *.jar; optional JDK/runtime JARs via --runtime or PROTOTYPE_RUNTIME_DIR.");
            System.err.println("  Mode 2 (--2, default): needs <dependencies-directory> as the first non-flag argument after target (or pass target only and same dir for both app+deps if combined).");
            System.err.println("  --1: Use HybridByteCodeTracer approach (ASM-based native detection)");
            System.err.println("  --2: SootUp Visitor Pattern (Worklist-based, Jimple analysis) [DEFAULT]");
            System.err.println("  --runtime DIR: JARs in DIR on classloader only (Mode 1); also PROTOTYPE_RUNTIME_DIR");
            return;
        }

        String targetDir = args[0];

        boolean hybridByteCodeTracer = false;
        boolean sootupVisitorPattern = false;
        String depsDir = null;
        boolean modeExplicit = false;

        for (int i = 1; i < args.length; i++) {
            String a = args[i];
            if ("--1".equals(a)) {
                hybridByteCodeTracer = true;
                modeExplicit = true;
            } else if ("--2".equals(a)) {
                sootupVisitorPattern = true;
                modeExplicit = true;
            } else if ("--runtime".equals(a)) {
                if (i + 1 >= args.length) {
                    System.err.println("--runtime requires a directory argument");
                    return;
                }
                i++;
            } else if (!a.startsWith("--")) {
                if (depsDir != null) {
                    System.err.println("Unexpected extra positional argument: " + a);
                    return;
                }
                depsDir = a;
            } else {
                System.err.println("Unknown flag: " + a);
                return;
            }
        }

        if (!hybridByteCodeTracer && !sootupVisitorPattern) {
            sootupVisitorPattern = true;
        }
        if (hybridByteCodeTracer && sootupVisitorPattern) {
            System.err.println("Specify at most one of --1 or --2");
            return;
        }
        if (sootupVisitorPattern && (depsDir == null || depsDir.isEmpty())) {
            System.err.println("Mode 2 requires <dependencies-directory> after <target-directory> (non-flag positional).");
            return;
        }

        if (hybridByteCodeTracer && depsDir != null) {
            System.out.println("INFO: Mode 1 ignores <dependencies-directory>; scanning JARs under target only: " + targetDir);
        }

        if (hybridByteCodeTracer) {
            System.out.println("Mode 1: HybridByteCodeTracer approach (ASM-based)");
        } else {
            System.out.println("Mode 2: SootUp Visitor Pattern (Worklist-based)" + (!modeExplicit ? " [DEFAULT]" : ""));
        }

        System.out.println("=== PrototypeFinal: Native Method Tracer ===");
        System.out.println("Target directory: " + targetDir);
        if (depsDir != null) {
            System.out.println("Dependencies directory: " + depsDir);
        }

        List<File> runtimeJars = collectRuntimeJarDirectories(args);

        // Mode 1: HybridByteCodeTracer approach
        if (hybridByteCodeTracer) {
            System.out.println("\n=== Mode 1: HybridByteCodeTracer Approach ===");
            try {
                runHybridByteCodeTracer(targetDir, runtimeJars);
            } catch (Exception e) {
                System.err.println("Error running HybridByteCodeTracer: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }

        // Mode 2: SootUp Visitor Pattern (Worklist-based)
        if (sootupVisitorPattern) {
            System.out.println("\n=== Mode 2: SootUp Visitor Pattern (Worklist) ===");
            try {
                runSootUpVisitorPattern(targetDir, depsDir);
            } catch (Exception e) {
                System.err.println("Error running SootUp Visitor Pattern: " + e.getMessage());
                e.printStackTrace();
            }
            return;
        }
    }
    private static void writeStringToFile(String content, File file) throws IOException {
        File parent = file.getParentFile();
        if (parent != null && !parent.exists()) {
            parent.mkdirs();
        }
        try (FileWriter fw = new FileWriter(file)) {
            fw.write(content);
        }
    }

    /**
     * Derive the per-container output directory from an anchor directory (Mode 1: target;
     * Mode 2: dependencies directory).
     *
     * Mapping (matches the JARFILES_/LIBS_/outputs_ convention used elsewhere
     * in this repo: see mapped_updated.py, extract_container_jdk.py, etc.):
     *
     *   JARFILES_solr_8.7.0_with_jdk    -> outputs_solr_8.7.0
     *   JARFILES_zookeeper_3.4.14       -> outputs_zookeeper_3.4.14
     *   JARFILES_cassandra_5.0.6-bookworm -> outputs_cassandra_5.0.6-bookworm
     *   /tmp/some_other_dir             -> outputs_some_other_dir
     *
     * The output directory is created if it does not exist.  An explicit
     * override is honoured via the system property `prototype.output.dir`.
     * Returns an absolute path string.
     */
    private static String resolveOutputDir(String anchorDir) {
        String override = System.getProperty("prototype.output.dir");
        if (override != null && !override.isEmpty()) {
            File od = new File(override);
            if (!od.exists()) od.mkdirs();
            return od.getAbsolutePath();
        }
        File anchor = new File(anchorDir).getAbsoluteFile();
        String basename = anchor.getName();
        String imgSafe = basename;
        if (imgSafe.startsWith("JARFILES_")) {
            imgSafe = imgSafe.substring("JARFILES_".length());
        }
        if (imgSafe.endsWith("_with_jdk")) {
            imgSafe = imgSafe.substring(0, imgSafe.length() - "_with_jdk".length());
        }
        if (imgSafe.isEmpty()) imgSafe = "default";
        File parent = anchor.getParentFile();
        File outDir = (parent != null)
                ? new File(parent, "outputs_" + imgSafe)
                : new File("outputs_" + imgSafe);
        if (!outDir.exists()) outDir.mkdirs();
        return outDir.getAbsolutePath();
    }

    /**
     * JARs from runtime directories: used on the URLClassLoader for invoke
     * resolution only (Mode 1). Not scanned by {@link #traceJarFiles}.
     * Sources: {@code PROTOTYPE_RUNTIME_DIR}, then any {@code --runtime DIR}
     * pairs in {@code args} after {@code args[0]} (tokens {@code --1} / {@code --2} are skipped).
     */
    private static List<File> collectRuntimeJarDirectories(String[] args) {
        LinkedHashSet<File> jars = new LinkedHashSet<>();
        String env = System.getenv("PROTOTYPE_RUNTIME_DIR");
        if (env != null && !env.isEmpty()) {
            addRuntimeJarsFromDirectory(new File(env), jars);
        }
        for (int i = 1; i < args.length; i++) {
            if ("--1".equals(args[i]) || "--2".equals(args[i])) {
                continue;
            }
            if ("--runtime".equals(args[i]) && i + 1 < args.length) {
                addRuntimeJarsFromDirectory(new File(args[++i]), jars);
            }
        }
        return new ArrayList<>(jars);
    }

    private static void addRuntimeJarsFromDirectory(File dir, LinkedHashSet<File> out) {
        if (!dir.isDirectory()) {
            System.err.println("ERROR: --runtime / PROTOTYPE_RUNTIME_DIR is not a directory: "
                    + dir.getAbsolutePath()
                    + " — invoke tracing cannot load JDK/application classes from the runtime JARs.");
            return;
        }
        File[] list = dir.listFiles((d, name) -> name.endsWith(".jar"));
        if (list == null || list.length == 0) {
            System.err.println("WARN: No .jar files under runtime directory: " + dir.getAbsolutePath()
                    + " — did you pass a typo? (Use: --runtime /path/to/dir, not the word DIR.)");
            return;
        }
        Arrays.sort(list, Comparator.comparing(File::getName));
        for (File f : list) {
            if (f.isFile()) {
                out.add(f.getAbsoluteFile());
            }
        }
    }


    /**
     * Executes HybridByteCodeTracer analysis (Mode 1)
     *
     * FUNCTION NAME: runHybridByteCodeTracer
     *
     * USAGE:
     *   Called internally when --1 mode is selected
     * 
     * INPUT REQUIRED:
     *   - targetDir: Directory containing application JAR files to scan (all *.jar are analyzed)
     *   - runtimeOnlyJars: Optional runtime flat JARs (e.g. java.base) on the loader only
     *
     * WHAT IT'S USED FOR:
     *   - Performs ASM-based bytecode analysis for native method detection
     *   - Scans JAR files using ASM ClassReader to find native methods
     *   - Traces method calls through bytecode instructions
     *   - Generates comprehensive native method usage report
     *   - Provides performance timing information
     *
     * PROCESS:
     *   1. Set up path prefix to targetDir (same directory lists scan roots)
     *   2. Get list of JAR files to analyze
     *   3. Extract class files from each JAR
     *   4. Use ASM to analyze bytecode for native method calls
     *   5. Trace method invocation chains
     *   6. Write results to output file
     *   7. Display performance metrics
     */
    private static void runHybridByteCodeTracer(String targetDir, List<File> runtimeOnlyJars) throws IOException {
        System.out.println("Starting HybridByteCodeTracer analysis...");

        pathPrefix = targetDir;
        if (!pathPrefix.endsWith("/")) {
            pathPrefix += "/";
        }

        // Pin the Mode-1 results file under outputs_<IMG_SAFE>/ derived from targetDir.
        String outputDir = resolveOutputDir(targetDir);
        NATIVE_METHODS_FILE = outputDir + "/native_methods.txt";
        System.out.println("INFO: Output directory: " + outputDir);

        long startTime = System.currentTimeMillis();
        List<String> jarPathResult = new ArrayList<>();
        Set<String> nativeMethodResult = new HashSet<>();
        GetJarPaths getJarPaths = new GetJarPaths();

        List<String> classPathResult = new ArrayList<>();
        FindJarClass findJarClass = new FindJarClass();

        FindNativeMethods findNativeMethods = new FindNativeMethods();
        
        try {
            jarPathResult = getJarPaths.getJarPaths();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        for(String jarPath : jarPathResult){
            jarPath = pathPrefix + jarPath;
            File file = new File(jarPath);
            if (!file.exists() || !file.isFile()){
                System.out.println("JAR file not found: " + jarPath);
                continue;
            }
            classPathResult.addAll(findJarClass.findClass(jarPath));
            nativeMethodResult.addAll(findNativeMethods.findNativeMethods(jarPath));
        }

        // Build a URLClassLoader from target JARs so that MethodPrinter
        // resolves classes from the target application, not the analysis JVM.
        List<URL> jarUrls = new ArrayList<>();
        for (String jp : jarPathResult) {
            try {
                File jf = new File(pathPrefix + jp);
                if (jf.exists()) {
                    jarUrls.add(jf.toURI().toURL());
                }
            } catch (MalformedURLException e) {
                System.err.println("Bad JAR URL: " + pathPrefix + jp);
            }
        }
        for (File rj : runtimeOnlyJars) {
            try {
                if (rj.exists() && rj.isFile()) {
                    jarUrls.add(rj.toURI().toURL());
                } else {
                    System.err.println("WARN: Runtime JAR missing, skipping: " + rj);
                }
            } catch (MalformedURLException e) {
                System.err.println("Bad runtime JAR URL: " + rj);
            }
        }
        targetClassLoader = new URLClassLoader(jarUrls.toArray(new URL[0]), null) {
            @Override
            public InputStream getResourceAsStream(String name) {
                // Only search target JARs — skip bootstrap classloader delegation
                // to prevent JDK 11 classes leaking into JDK 8 analysis results.
                URL url = findResource(name);
                if (url == null) return null;
                try { return url.openStream(); }
                catch (IOException e) { return null; }
            }
        };
        System.out.println("INFO: Target classloader: " + jarPathResult.size()
                + " scan JARs under target + " + runtimeOnlyJars.size() + " runtime (invoke-only) JARs"
                + " = " + jarUrls.size() + " URLs total");

        if (!runtimeOnlyJars.isEmpty()) {
            System.out.println("INFO: Runtime (invoke-only) JARs — not exhaustively scanned:");
            for (File rj : runtimeOnlyJars) {
                System.out.println("    " + rj.getAbsolutePath());
            }
        }

        System.out.println("DEBUG: classpath: " + classPathResult);
        System.out.println(classPathResult.size());
        System.out.println("There are " + classPathResult.size() + " classes over all\n");
        
        System.out.println("Now we start to analyze called native methods!");
        Util.println();
        PrototypeFinal bct = new PrototypeFinal();
        bct.traceJarFiles(jarPathResult);
        bct.prettyPrint();
        bct.writeToFile();

        if (targetClassLoader != null) {
            try { targetClassLoader.close(); } catch (IOException e) { /* ignore */ }
            targetClassLoader = null;
        }

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("Time taken: " + totalTimeInSeconds + " seconds");
    }

    /**
     * Executes SootUp Visitor Pattern analysis (Mode 2)
     *
     * FUNCTION NAME: runSootUpVisitorPattern
     *
     * USAGE:
     *   Called internally when --2 mode is selected
     *
     * INPUT REQUIRED:
     *   - targetDir: Directory containing target application JAR files
     *   - depsDir: Directory containing dependency JAR files
     *
     * WHAT IT'S USED FOR:
     *   - Performs SootUp-based Jimple analysis using visitor pattern
     *   - Similar to Mode 1 but uses SootUp/Jimple instead of ASM/bytecode
     *   - Worklist-based traversal without explicit DFS/BFS
     *   - Traces method calls through Jimple statements
     *   - Generates comprehensive native method usage report
     *
     * PROCESS:
     *   1. Load JARs and build SootUp view
     *   2. Get all classes from target and dependencies
     *   3. Visit each class and analyze methods
     *   4. Use visitor pattern to process Jimple statements
     *   5. Track visited methods to avoid duplicates
     *   6. Write results to output file
     *   7. Display performance metrics
     */
    private static void runSootUpVisitorPattern(String targetDir, String depsDir) throws IOException {
        System.out.println("Starting SootUp Visitor Pattern analysis (Method-based worklist)...");

        long startTime = System.currentTimeMillis();

        // ========== DATA STRUCTURES FOR ANALYSIS ==========

        // Track visited methods to prevent duplicate analysis and infinite loops
        // Contains method signatures in SootUp format: "<ClassName: ReturnType methodName(ParamTypes)>"
        Set<String> visitedMethods = new HashSet<>();

        // Store all discovered native methods (final output)
        // Simple format: "ClassName.methodName" (e.g., "java.lang.System.currentTimeMillis")
        Set<String> nativeMethods = new HashSet<>();

        // Call graph generation removed - Mode 2 now only finds all reachable natives
        // similar to Mode 1 but using SootUp/Jimple instead of ASM

        // ========== LOAD JAR FILES ==========

        // Recursively scan target and dependency directories for JAR files
        // This also populates:
        //   - targetJarClasses: Set of all class names found in target JARs
        //   - dependencyClasses: Set of all class names found in dependency JARs
        //   - classToJar: Map from class name to the JAR file containing it
        List<String> targetJars = loadJarsFromDirectory(targetDir, targetJarClasses, classToJar, "target");
        List<String> depJars = loadJarsFromDirectory(depsDir, dependencyClasses, classToJar, "dependency");

        System.out.println("Target JARs contain " + targetJarClasses.size() + " classes");
        System.out.println("Dependencies contain " + dependencyClasses.size() + " classes");

        // ========== BUILD SOOTUP VIEW ==========

        // SootUp's "view" is the core abstraction for analyzing Java code
        // It provides:
        //   1. Method resolution: Look up method signatures and get their implementations
        //   2. Jimple access: Convert bytecode to Jimple intermediate representation
        //   3. Class hierarchy: Understand inheritance and interface relationships
        //
        // We add three types of input locations:
        //   1. Target JARs: The application we're analyzing
        //   2. Dependency JARs: Libraries the application uses
        //   3. JRE runtime: Standard Java libraries (java.lang.*, java.util.*, etc.)
        List<AnalysisInputLocation> inputs = new ArrayList<>();
        for (String jar : targetJars) inputs.add(new JavaClassPathAnalysisInputLocation(jar));
        for (String depJar : depJars) inputs.add(new JavaClassPathAnalysisInputLocation(depJar));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());  // Adds JRE classes
        JavaView view = new JavaView(inputs);

        System.out.println("\nStarting method-based worklist analysis..");

        // ========== INITIALIZE METHOD WORKLIST ==========

        // METHOD-BASED WORKLIST (not class-based!)
        // This is the key approach: we follow method calls transitively, just like Mode 1
        //
        // The worklist algorithm:
        //   1. Start with all methods from the target application
        //   2. Process each method to find what it calls
        //   3. Add called methods to the worklist
        //   4. Repeat until worklist is empty (fixed-point)
        //
        // This creates a TRANSITIVE CLOSURE of all reachable methods from the application
        Queue<MethodSignature> methodWorklist = new LinkedList<>();

        // Initialize worklist with all methods from target classes
        // (Similar to Mode 1 starting from classes in the target JARs)
        for (String className : targetJarClasses) {
            Optional<JavaSootClass> classOpt = view.getClass(
                view.getIdentifierFactory().getClassType(className)
            );
            if (classOpt.isPresent()) {
                for (JavaSootMethod method : classOpt.get().getMethods()) {
                    methodWorklist.add(method.getSignature());
                }
            }
        }

        // Also add dependency methods (if you want to be comprehensive)
        for (String className : dependencyClasses) {
            Optional<JavaSootClass> classOpt = view.getClass(
                view.getIdentifierFactory().getClassType(className)
            );
            if (classOpt.isPresent()) {
                for (JavaSootMethod method : classOpt.get().getMethods()) {
                    methodWorklist.add(method.getSignature());
                }
            }
        }

        System.out.println("Initial worklist size: " + methodWorklist.size() + " methods");

        int processedMethods = 0;
        int progressInterval = 100;

        // ========== MAIN WORKLIST PROCESSING LOOP ==========
        // Process methods one by one, following calls transitively
        // This implements a worklist-based fixed-point algorithm
        while (!methodWorklist.isEmpty()) {
            // STEP 1: Dequeue the next method from the worklist
            MethodSignature methodSig = methodWorklist.poll();
            String methodId = methodSig.toString();

            // STEP 2: Skip if already visited (prevents infinite loops and duplicate work)
            if (visitedMethods.contains(methodId)) {
                continue;
            }
            visitedMethods.add(methodId);

            // STEP 3: Progress reporting (shows analysis is progressing)
            processedMethods++;
            if (processedMethods % progressInterval == 0) {
                System.out.println("  Processed " + processedMethods + " methods, found " +
                                 nativeMethods.size() + " natives...");
            }

            // STEP 4: Try to get the method implementation from SootUp view
            // This may fail if the method is from a missing dependency
            Optional<JavaSootMethod> methodOpt = view.getMethod(methodSig);
            if (!methodOpt.isPresent()) {
                continue;
            }

            JavaSootMethod method = methodOpt.get();
            String className = methodSig.getDeclClassType().getFullyQualifiedName();

            // STEP 5: Check if this method is native
            // This is equivalent to checking the ACC_NATIVE flag in bytecode (Mode 1)
            // If native, record it in our results set
            if (method.getModifiers().contains(MethodModifier.NATIVE)) {
                String nativeName = className + "." + method.getName();
                nativeMethods.add(nativeName);
                System.out.println("[ * Found native method * ] " + nativeName);
            }

            // STEP 6: Skip methods without a body (abstract, native, interface methods)
            // We can't analyze calls from these methods since there's no implementation
            if (!method.hasBody()) {
                continue;
            }

            // STEP 7: Analyze method body to find all method calls (KEY STEP!)
            // This is where we build the call graph and find natives transitively
            try {
                // Get the method's Jimple IR (intermediate representation)
                // Jimple is a 3-address code format that's easier to analyze than bytecode
                Body body = method.getBody();

                // Process all statements in the method to find method invocations
                // Jimple statements include assignments, calls, conditionals, etc.
                for (Object stmtObj : body.getStmts()) {
                    // Check if this statement is a method invocation
                    // InvokableStmt represents method calls (virtual, static, special, interface, dynamic)
                    if (stmtObj instanceof InvokableStmt) {
                        ((InvokableStmt) stmtObj).getInvokeExpr().ifPresent(invokeExpr -> {
                            // Extract the signature of the method being called
                            MethodSignature callee = invokeExpr.getMethodSignature();
                            String calleeId = callee.toString();
                            String calleeClassName = callee.getDeclClassType().getFullyQualifiedName();

                            // Call graph edge building removed - we now only track reachability
                            // No longer building caller/callee relationships

                            // Add the called method to the worklist if not already visited
                            // This is the TRANSITIVE part - we follow calls into JRE, libraries, etc.
                            // Eventually we'll reach all methods reachable from the application
                            if (!visitedMethods.contains(calleeId)) {
                                methodWorklist.add(callee);
                            }
                        });
                    }
                }
            } catch (VerifyError | Exception e) {
                // Skip methods that can't be analyzed due to verification errors
                // This can happen with malformed bytecode or SootUp limitations
                // Same defensive error handling approach as Mode 1
            }
        }

        // Write results to the same outputs_<IMG_SAFE>/ directory used by Mode 1.
        String outputDir = resolveOutputDir(depsDir);
        String outputFile = outputDir + "/sootup_visitor_natives.txt";
        writeMode2Results(outputFile, nativeMethods, visitedMethods.size());

        // Call graph and call chain generation removed
        // Mode 2 now only outputs the list of reachable natives

        long endTime = System.currentTimeMillis();
        long totalTime = endTime - startTime;
        double totalTimeInSeconds = (double) totalTime / 1000;
        System.out.println("\nAnalysis complete!");
        System.out.println("Time taken: " + totalTimeInSeconds + " seconds");
        System.out.println("Total methods visited: " + visitedMethods.size());
        System.out.println("Native methods found: " + nativeMethods.size());
    }

    /**
     * Writes Mode 2 results to file
     */
    private static void writeMode2Results(String filename, Set<String> nativeMethods, int totalVisited) {
        try {
            StringBuilder content = new StringBuilder();
            content.append("=== SootUp Visitor Pattern Analysis Results ===\n\n");
            content.append("Total methods visited: ").append(totalVisited).append("\n");
            content.append("Total native methods found: ").append(nativeMethods.size()).append("\n\n");
            content.append("Native Methods:\n");
            content.append("===============\n");

            List<String> sortedNatives = new ArrayList<>(nativeMethods);
            Collections.sort(sortedNatives);

            for (String nativeMethod : sortedNatives) {
                content.append(nativeMethod).append("\n");
            }

            File file = new File(filename);
            FileWriter fw = new FileWriter(file.getAbsolutePath());
            fw.write(content.toString());
            fw.close();

            System.out.println("\nResults written to: " + file.getAbsolutePath());
        } catch (IOException e) {
            System.err.println("Error writing results: " + e.getMessage());
            e.printStackTrace();
        }
    }


    /**
     * Traces all classes within JAR files for native method calls
     * 
     * FUNCTION NAME: traceJarFiles
     * 
     * USAGE:
     *   Called internally to process JAR files and extract class analysis
     * 
     * INPUT REQUIRED:
     *   - jarPaths: List of JAR file paths (relative to pathPrefix)
     * 
     * WHAT IT'S USED FOR:
     *   - Opens JAR files and extracts all .class files
     *   - Analyzes each class file using ASM ClassReader
     *   - Detects native methods and method calls within JAR contents
     *   - Handles JAR file I/O and error recovery
     * 
     * PROCESS:
     *   1. Iterate through each JAR file path
     *   2. Construct full path using pathPrefix
     *   3. Open JAR file and enumerate entries
     *   4. Process each .class file using ASM
     *   5. Handle errors gracefully and continue processing
     */
    public void traceJarFiles(List<String> jarPaths) throws IOException {
        for (String jarPath : jarPaths) {
            String fullJarPath = pathPrefix + jarPath;
            File file = new File(fullJarPath);
            if (!file.exists() || !file.isFile()) {
                System.out.println("JAR file not found: " + fullJarPath);
                continue;
            }

            try (JarFile jarFile = new JarFile(fullJarPath)) {
                Enumeration<JarEntry> entries = jarFile.entries();
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    if (entry.getName().endsWith(".class")) {
                        try (InputStream inputStream = jarFile.getInputStream(entry)) {
                            ClassReader cr = new ClassReader(inputStream);
                            ClassPrinter cp = new ClassPrinter();
                            cr.accept(cp, 0);
                        } catch (Exception e) {
                            System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                        }
                    }
                }
            } catch (Exception e) {
                System.err.println("Error processing JAR " + fullJarPath + ": " + e.getMessage());
            }
        }
    }

    /**
     * Writes discovered native methods to output file
     * 
     * FUNCTION NAME: writeToFile
     * 
     * USAGE:
     *   Called internally after analysis completion to save results
     * 
     * INPUT REQUIRED:
     *   - None (uses static Util.visitedNative set)
     * 
     * WHAT IT'S USED FOR:
     *   - Saves all discovered native methods to elasticsearch_hybrid.txt
     *   - Creates output file if it doesn't exist
     *   - Provides summary of total native methods found
     *   - Handles file I/O operations safely
     * 
     * PROCESS:
     *   1. Collect all native methods from Util.visitedNative
     *   2. Create or open output file
     *   3. Write each native method on a separate line
     *   4. Close file and display summary
     */
    public void writeToFile() {
        try {
            // Build native methods content
            StringBuilder nativeContentBuilder = new StringBuilder();
            for (String m : Util.visitedNative) {
                nativeContentBuilder.append(m).append("\n");
            }
            String nativeContent = nativeContentBuilder.toString();

            // Write to files
            File nativeOutput = new File(NATIVE_METHODS_FILE);

            writeStringToFile(nativeContent, nativeOutput);

            // Print single consolidated output message
            System.out.println("Analysis results written to:");
            System.out.println("  - Native methods (" + Util.visitedNative.size() + "): " + nativeOutput.getAbsolutePath());
        } catch(IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Displays analysis summary statistics
     * 
     * FUNCTION NAME: prettyPrint
     * 
     * USAGE:
     *   Called internally to display analysis results summary
     * 
     * INPUT REQUIRED:
     *   - None (uses static Util sets for statistics)
     * 
     * WHAT IT'S USED FOR:
     *   - Displays count of visited methods during analysis
     *   - Shows count of discovered native methods
     *   - Provides visual separator for output formatting
     *   - Informs user about file output location
     * 
     * PROCESS:
     *   1. Print visual separator line
     *   2. Display visited method count
     *   3. Display native method count
     *   4. Inform about file output destination
     */
    public void prettyPrint() {
        Util.println();
        System.out.println("Count of visited methods: " + Util.visitedMethod.size() +
                "\n\nCount of called native methods: " + Util.visitedNative.size());
        Util.println();
    }


    /**
     * Loads JAR files from a directory and indexes their class contents
     * 
     * FUNCTION NAME: loadJarsFromDirectory
     * 
     * USAGE:
     *   Called internally to load target and dependency JAR files
     * 
     * INPUT REQUIRED:
     *   - dirPath: Directory path containing JAR files
     *   - classSet: Set to store discovered class names
     *   - classToJarMap: Map to store class name to JAR file mapping
     *   - type: String identifier for logging ("target" or "dependency")
     * 
     * WHAT IT'S USED FOR:
     *   - Recursively scans directory for JAR files
     *   - Extracts class names from each JAR file
     *   - Builds mapping between class names and their source JAR files
     *   - Populates class sets for analysis
     *   - Provides detailed logging of discovered JARs and classes
     * 
     * PROCESS:
     *   1. Validate directory exists and is accessible
     *   2. Use stack-based traversal to find all JAR files recursively
     *   3. Open each JAR file and enumerate entries
     *   4. Extract .class files and convert to class names
     *   5. Update class sets and mappings
     *   6. Handle I/O errors gracefully
     *   7. Return list of discovered JAR file paths
     */
    private static List<String> loadJarsFromDirectory(
            String dirPath,
            Set<String> classSet,
            Map<String, String> classToJarMap,
            String type
    ) {
        List<String> jarList = new ArrayList<>();
        File root = new File(dirPath);
        if (!root.exists() || !root.isDirectory()) {
            System.err.println(type + " directory does not exist or is not a directory: " + dirPath);
            return jarList;
        }
        Deque<File> stack = new ArrayDeque<>();
        stack.push(root);
        while (!stack.isEmpty()) {
            File dir = stack.pop();
            File[] files = dir.listFiles();
            if (files == null) continue;
            for (File f : files) {
                if (f.isDirectory()) {
                    stack.push(f);
                } else if (f.getName().endsWith(".jar")) {
                    System.out.println("Processing " + type + " JAR: " + f.getAbsolutePath());
                    jarList.add(f.getAbsolutePath());
                    try (ZipFile zipFile = new ZipFile(f)) {
                        Enumeration<? extends ZipEntry> entries = zipFile.entries();
                        while (entries.hasMoreElements()) {
                            ZipEntry entry = entries.nextElement();
                            String name = entry.getName();
                            if (name.endsWith(".class")) {
                                String className = name.replace('/', '.').substring(0, name.length() - 6);
                                classSet.add(className);
                                classToJarMap.put(className, f.getAbsolutePath());
                            }
                        }
                    } catch (IOException e) {
                        System.err.println("Error reading " + type + " JAR: " + f.getName() + " - " + e.getMessage());
                    }
                }
            }
        }
        System.out.println("Total " + type + " JARs found: " + jarList.size());
        System.out.println(type + " classes indexed: " + classSet.size());
        return jarList;
    }


    /**
     * Utility class for HybridByteCodeTracer functionality
     * 
     * CLASS NAME: Util
     * 
     * USAGE:
     *   Used internally by HybridByteCodeTracer methods for data storage and utilities
     * 
     * WHAT IT'S USED FOR:
     *   - Stores visited methods and native methods during analysis
     *   - Provides utility methods for file operations
     *   - Manages static collections for analysis state
     *   - Provides formatting utilities for output
     */
    static class Util {
        public static Set<String> visitedMethod = new HashSet<>();
        public static Set<String> visitedNative = new HashSet<>();

        /**
         * Prints visual separator line for output formatting
         *
         * FUNCTION NAME: println
         *
         * USAGE:
         *   Called internally for output formatting
         *
         * WHAT IT'S USED FOR:
         *   - Provides visual separation in console output
         *   - Improves readability of analysis results
         */
        public static void println() {
            System.out.println(" ");
        }
    }

    /**
     * ASM ClassVisitor for filtering specific methods in classes
     * 
     * CLASS NAME: ClassFilter
     * 
     * USAGE:
     *   Used internally by ASM to filter and analyze specific methods
     * 
     * WHAT IT'S USED FOR:
     *   - Filters classes to find specific method signatures
     *   - Detects native methods during bytecode analysis
     *   - Processes only methods matching specific identifier
     *   - Integrates with ASM framework for bytecode analysis
     */
    static class ClassFilter extends ClassVisitor {
        private String identifier;
        private String className;

        public ClassFilter(String identifier) {
            super(Opcodes.ASM9);
            this.identifier = identifier;
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (!this.identifier.equals(name+descriptor)) {
                return null;
            }
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    /**
     * ASM ClassVisitor for printing class information and detecting native methods
     * 
     * CLASS NAME: ClassPrinter
     * 
     * USAGE:
     *   Used internally by ASM to analyze class bytecode and detect native methods
     * 
     * WHAT IT'S USED FOR:
     *   - Visits class bytecode during ASM analysis
     *   - Detects and records native methods found in classes
     *   - Provides class information logging
     *   - Creates MethodPrinter for method-level analysis
     *   - Integrates with ASM framework for comprehensive analysis
     */
    static class ClassPrinter extends ClassVisitor {
        private String className;

        public ClassPrinter() {
            super(Opcodes.ASM9);
        }

        public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
            this.className = name.replace('/', '.');
        }

        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if ((access & 256) > 0) {
                System.out.println("[ * Find a native method * ] " + className + '.' +name);
                Util.visitedNative.add(className + '.' +name);
            }

            MethodVisitor mv = new MethodPrinter();
            return mv;
        }
    }

    /**
     * ASM MethodVisitor for analyzing method bytecode and tracing method calls
     * 
     * CLASS NAME: MethodPrinter
     * 
     * USAGE:
     *   Used internally by ASM to analyze method bytecode and trace calls
     * 
     * WHAT IT'S USED FOR:
     *   - Visits method bytecode during ASM analysis
     *   - Detects method invocation instructions (INVOKEVIRTUAL, INVOKESTATIC, etc.)
     *   - Traces method calls to find native methods
     *   - Prevents duplicate analysis of same methods
     *   - Recursively analyzes called methods using ClassReader
     *   - Integrates with ASM framework for method-level analysis
     */
    static class MethodPrinter extends MethodVisitor {
        public MethodPrinter() {
            super(Opcodes.ASM9);
        }

        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            String className = owner.replace('/', '.');
            if (Util.visitedMethod.contains(className+name+descriptor)) {
                return;
            }

            Util.visitedMethod.add(className+name+descriptor);
            try {
                String resourceName = className.replace('.', '/') + ".class";
                InputStream is = null;
                if (targetClassLoader != null) {
                    is = targetClassLoader.getResourceAsStream(resourceName);
                    // jmod / tooling sometimes leaves entries under classes/ rather than JAR root
                    if (is == null) {
                        is = targetClassLoader.getResourceAsStream("classes/" + resourceName);
                    }
                }
                if (is == null) {
                    return;
                }
                ClassReader cr = new ClassReader(is);
                is.close();
                ClassFilter cf = new ClassFilter(name+descriptor);
                cr.accept(cf, 0);
            } catch (IOException e) {
                // Class not found in target JARs — skip
            }

            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
        }
    }

    /**
     * Utility class for extracting class names from JAR files
     * 
     * CLASS NAME: FindJarClass
     * 
     * USAGE:
     *   Used internally to extract class file names from JAR archives
     * 
     * WHAT IT'S USED FOR:
     *   - Opens JAR files and enumerates entries
     *   - Extracts .class file names from JAR contents
     *   - Converts JAR entry names to fully qualified class names
     *   - Provides list of classes for further analysis
     *   - Handles JAR file I/O operations
     */
    static class FindJarClass {
        public List<String> findClass(String jarFileName) throws IOException {
            List<String> classPaths = new ArrayList<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    classPaths.add(entry.getName().replace(".class", "")
                            .replace("/", "."));
                }
            }

            jarFile.close();
            return classPaths;
        }
    }

    /**
     * Utility class for discovering JAR files in a directory
     * 
     * CLASS NAME: GetJarPaths
     * 
     * USAGE:
     *   Used internally to find all JAR files in a specified directory
     * 
     * WHAT IT'S USED FOR:
     *   - Scans directory for .jar files
     *   - Returns list of JAR file names (not full paths)
     *   - Validates directory existence and accessibility
     *   - Provides JAR file discovery for analysis pipeline
     *   - Handles directory I/O operations
     */
    static class GetJarPaths {
        public List<String> getJarPaths() throws IOException {
            ArrayList<String> result = new ArrayList<>();

            String jarDir = pathPrefix;
            File jarFolder = new File(jarDir);

            if (!jarFolder.exists() || !jarFolder.isDirectory()) {
                System.out.println("JAR directory not found: " + jarDir);
                return result;
            }

            File[] jarFiles = jarFolder.listFiles((dir, name) -> name.endsWith(".jar"));
            if (jarFiles != null) {
                for (File jarFile : jarFiles) {
                    result.add(jarFile.getName());
                    System.out.println("Found JAR: " + jarFile.getName());
                }
            }

            return result;
        }
    }

    /**
     * Utility class for finding native methods in JAR files using ASM
     * 
     * CLASS NAME: FindNativeMethods
     * 
     * USAGE:
     *   Used internally to scan JAR files for native method declarations
     * 
     * WHAT IT'S USED FOR:
     *   - Scans JAR files for classes containing native methods
     *   - Uses ASM to analyze class bytecode for native method flags
     *   - Extracts native method signatures and names
     *   - Provides comprehensive native method discovery
     *   - Handles JAR file processing and error recovery
     */
    static class FindNativeMethods {
        public Set<String> findNativeMethods(String jarFileName) throws IOException {
            Set<String> nativeMethods = new HashSet<>();
            JarFile jarFile = new JarFile(jarFileName);

            Enumeration<JarEntry> entries = jarFile.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();

                if (entry.getName().endsWith(".class")) {
                    try (InputStream inputStream = jarFile.getInputStream(entry)) {
                        ClassReader classReader = new ClassReader(inputStream);
                        classReader.accept(new NativeMethodVisitor(entry.getName(), nativeMethods), 0);
                    } catch (Exception e) {
                        System.err.println("Error processing class " + entry.getName() + ": " + e.getMessage());
                    }
                }
            }

            jarFile.close();
            return nativeMethods;
        }

        /**
         * ASM ClassVisitor for detecting native methods in class bytecode
         * 
         * CLASS NAME: NativeMethodVisitor
         * 
         * USAGE:
         *   Used internally by FindNativeMethods to analyze individual classes
         * 
         * WHAT IT'S USED FOR:
         *   - Visits class bytecode to detect native method declarations
         *   - Checks method access flags for native modifier
         *   - Records native method signatures in specified format
         *   - Integrates with ASM framework for bytecode analysis
         *   - Handles class name conversion and formatting
         */
        private static class NativeMethodVisitor extends ClassVisitor {
            private final String className;
            private final Set<String> nativeMethods;

            public NativeMethodVisitor(String className, Set<String> nativeMethods) {
                super(Opcodes.ASM9);
                this.className = className;
                this.nativeMethods = nativeMethods;
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
                if ((access & Opcodes.ACC_NATIVE) != 0) {
                    String jniFunction = className.replace(".class", "")
                            .replace("/", ".")+ "." + name + "---" + descriptor;
                    nativeMethods.add(jniFunction);
                }
                return null;
            }
        }
    }
}
