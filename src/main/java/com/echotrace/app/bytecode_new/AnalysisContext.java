package com.echotrace.app.bytecode_new;

import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.model.SootClass;
import sootup.core.model.SootMethod;
import sootup.java.bytecode.frontend.inputlocation.DefaultRuntimeAnalysisInputLocation;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.views.JavaView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static com.echotrace.app.bytecode_new.DetectorSupport.*;

/**
 * Shared, parse-once analysis context for the whole detector family.
 *
 * Building this is THE expensive step: jar indexing, SootUp view creation,
 * class resolution, and Jimple body construction (warm-up) all happen exactly
 * once here. Detectors then run over the cached structures — sequentially or
 * in parallel — without re-parsing anything.
 *
 * Thread-safety: after {@link #build}, all fields are immutable and every
 * method body has already been built and cached, so concurrent detectors only
 * perform reads. Disable warm-up parallelism (and detector parallelism in the
 * orchestrator) with -Ddetector.parallel=false if your SootUp version's cache
 * misbehaves under concurrency.
 */
final class AnalysisContext {

    final String targetDir;
    /** All jars under targetDir (including jna-*, jnr-*, ... framework jars). */
    final List<String> allJars;
    /** class FQCN -> jar basename, over ALL jars (used by dyn + ffi detectors). */
    final Map<String, String> classToJarAll;
    /** class FQCN -> jar basename, framework/runtime jars excluded (iface + directmap). */
    final Map<String, String> classToJarScan;
    /** Mapped native library names from the target dir (NativeLibraryNames). */
    final Map<String, String> nativeLibraryNames;
    /** The single shared view (target jars + detector.runtime.dir + host JRE fallback). */
    final JavaView view;
    /** Resolved classes from ALL jars, outer classes first. Unmodifiable. */
    final List<SootClass> targetClassesAll;
    /** Subset of {@link #targetClassesAll} from non-framework jars. Unmodifiable. */
    final List<SootClass> targetClassesScan;

    private AnalysisContext(String targetDir, List<String> allJars,
                            Map<String, String> classToJarAll, Map<String, String> classToJarScan,
                            Map<String, String> nativeLibraryNames, JavaView view,
                            List<SootClass> targetClassesAll, List<SootClass> targetClassesScan) {
        this.targetDir = targetDir;
        this.allJars = Collections.unmodifiableList(allJars);
        this.classToJarAll = Collections.unmodifiableMap(classToJarAll);
        this.classToJarScan = Collections.unmodifiableMap(classToJarScan);
        this.nativeLibraryNames = Collections.unmodifiableMap(nativeLibraryNames);
        this.view = view;
        this.targetClassesAll = Collections.unmodifiableList(targetClassesAll);
        this.targetClassesScan = Collections.unmodifiableList(targetClassesScan);
    }

    /** Builds with the container runtime taken from -Ddetector.runtime.dir only. */
    static AnalysisContext build(String targetDir) {
        return build(targetDir, null);
    }

    /**
     * @param runtimeDir container runtime jar directory (e.g. RUNTIME_&lt;app&gt;);
     *                   its .jar files join the analysis classpath so runtime
     *                   classes resolve from the CONTAINER's Java, not the
     *                   host's. The host JRE remains only as a last-resort
     *                   fallback for classes the runtime dir doesn't carry.
     *                   May be null. -Ddetector.runtime.dir jars are also
     *                   honored either way. Note: .jmod files cannot go on a
     *                   classpath — extract them to jars if needed.
     */
    static AnalysisContext build(String targetDir, String runtimeDir) {
        long t0 = System.currentTimeMillis();

        List<String> allJars = collectJarPaths(targetDir);
        if (allJars.isEmpty()) {
            throw new IllegalArgumentException("no .jar files found under: " + targetDir);
        }
        List<String> scanJars = targetScanJars(allJars);

        Map<String, String> classToJarAll = collectClassToJar(allJars);
        Map<String, String> classToJarScan = collectClassToJar(scanJars);
        Map<String, String> nativeLibraryNames = NativeLibraryNames.fromTargetDir(targetDir);

        // Classpath order matters: target jars first, then the container
        // runtime, with the host JRE location last — first match wins.
        List<String> cpJars = analysisClasspathJars(allJars); // + detector.runtime.dir
        if (runtimeDir != null && !runtimeDir.trim().isEmpty()) {
            List<String> runtimeJars = collectJarPaths(runtimeDir.trim());
            cpJars.addAll(runtimeJars);
            System.out.println("[CTX] container runtime jars: " + runtimeJars.size()
                    + " from " + runtimeDir);
        }

        System.out.println("[CTX] jars=" + allJars.size()
                + " (scan=" + scanJars.size() + ", cp=" + cpJars.size() + ")"
                + " classes=" + classToJarAll.size()
                + " (scan=" + classToJarScan.size() + ")");

        List<AnalysisInputLocation> inputs = new ArrayList<>();
        inputs.add(new JavaClassPathAnalysisInputLocation(toClassPath(cpJars)));
        inputs.add(new DefaultRuntimeAnalysisInputLocation());
        JavaView view = new JavaView(inputs);

        List<SootClass> targetClassesAll = resolveTargetClasses(view, classToJarAll.keySet());
        sortOuterClassesFirst(targetClassesAll);
        List<SootClass> targetClassesScan = new ArrayList<>(targetClassesAll.size());
        for (SootClass sc : targetClassesAll) {
            if (classToJarScan.containsKey(sc.getType().getFullyQualifiedName())) {
                targetClassesScan.add(sc);
            }
        }
        System.out.println("[CTX] resolved classes=" + targetClassesAll.size()
                + " (scan=" + targetClassesScan.size() + ")");

        warmUp(targetClassesAll);

        System.out.println("[CTX] shared context ready in "
                + ((System.currentTimeMillis() - t0) / 1000) + "s");
        return new AnalysisContext(targetDir, allJars, classToJarAll, classToJarScan,
                nativeLibraryNames, view, targetClassesAll, targetClassesScan);
    }

    /**
     * Forces Jimple body construction for every method ONCE, up front.
     * SootUp caches bodies per method, so after this pass every detector
     * sweep is a cheap read over cached IR. Errors are swallowed here; each
     * detector still hits (and logs) them per-method via its own try/catch.
     */
    private static void warmUp(List<SootClass> classes) {
        long t0 = System.currentTimeMillis();
        boolean parallel = !"false".equals(System.getProperty("detector.parallel"));
        Stream<SootClass> stream = parallel ? classes.parallelStream() : classes.stream();
        stream.forEach(sc -> {
            for (SootMethod m : sc.getMethods()) {
                try {
                    if (m.hasBody()) {
                        m.getBody().getStmts().size(); // force + cache
                    }
                } catch (Throwable ignored) {
                    // logged later by the detectors' per-method handling
                }
            }
        });
        System.out.println("[CTX] body warm-up (" + (parallel ? "parallel" : "sequential")
                + ") done in " + ((System.currentTimeMillis() - t0) / 1000) + "s");
    }
}
