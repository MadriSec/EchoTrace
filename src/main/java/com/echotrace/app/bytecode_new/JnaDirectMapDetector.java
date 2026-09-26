package com.echotrace.app.bytecode_new;

import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.ClassConstant;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.JAssignStmt;
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
 * JNA Direct Mapping Detector (Target-only analysis)
 *
 * Detects JNA direct-mapped native calls:
 *   class CLibrary {
 *       static { Native.register("c"); }
 *       public static native int strlen(String s);
 *   }
 *   CLibrary.strlen("hello")  ->  lib="c", symbol="strlen"
 *
 * The library name comes from Native.register("c") or
 * Native.register(NativeLibrary.getInstance("c", ...)).
 * The symbol name is the native method name itself (JNA convention).
 *
 * For Native.register(Class, ...) the registered class is the Class
 * ARGUMENT (resolved from a class constant when possible), not the class
 * containing the call site.
 *
 * Usage:
 *   mvn exec:java -Dexec.mainClass=com.echotrace.app.bytecode_new.JnaDirectMapDetector \
 *     -Dexec.args="<target-jars-dir> [outDir]" \
 *     [-Ddetector.runtime.dir=<extra-classpath-dir>] [-Ddetector.debug=true]
 *
 * Outputs:
 *   - jna_directmap_hits.txt   (native method declarations with lib/symbol/jar)
 *   - skipped_methods.txt      (methods that failed analysis)
 */
public final class JnaDirectMapDetector {

    private static final String JNA_NATIVE         = "com.sun.jna.Native";
    private static final String JNA_NATIVE_LIBRARY = "com.sun.jna.NativeLibrary";

    private static final String API_REGISTER_STRING              = "Native.register(String)";
    private static final String API_REGISTER_CLASS_STRING        = "Native.register(Class,String)";
    private static final String API_REGISTER_NATIVELIBRARY       = "Native.register(NativeLibrary)";
    private static final String API_REGISTER_CLASS_NATIVELIBRARY = "Native.register(Class,NativeLibrary)";
    private static final String API_UNKNOWN                      = "<?>";
    private static final String UNRESOLVED_LIB                   = "<?>";

    /** Max fixed-point iterations when summarizing string-returning helpers. */
    private static final int MAX_SUMMARY_ITERATIONS = 5;

    // Instance state (no mutable statics: safe to reuse / run twice / test).
    /** registered class FQCN -> RegisterInfo(lib, apiPattern) */
    private final Map<String, RegisterInfo> classToReg = new HashMap<>();
    /** method signature -> constant String it returns (helper summaries) */
    private final Map<String, String> methodStringReturns = new HashMap<>();

    private static final class RegisterInfo {
        final String lib;
        final String apiPattern;

        RegisterInfo(String lib, String apiPattern) {
            this.lib = lib;
            this.apiPattern = apiPattern;
        }

        boolean isResolved() {
            return !UNRESOLVED_LIB.equals(lib);
        }
    }

    public static void main(String[] args) throws IOException {
        if (args.length < 1) {
            System.err.println("Usage: JnaDirectMapDetector <target-jars-dir> [outDir]");
            System.exit(1);
        }

        String targetDir = args[0];
        String outDir = (args.length >= 2) ? args[1] : deriveDefaultOutDir(targetDir);

        File out = new File(outDir);
        if (!out.exists() && !out.mkdirs()) {
            throw new IOException("Failed to create outDir: " + out.getAbsolutePath());
        }

        new JnaDirectMapDetector().run(AnalysisContext.build(targetDir), out);
    }

    /** Runs over a shared, pre-parsed context (standalone main builds its own). */
    void run(AnalysisContext ctx, File out) throws IOException {
        File hitsFile = new File(out, "jna_directmap_hits.txt");
        File skippedFile = new File(out, "skipped_methods.txt");

        // Framework/runtime jars stay on the analysis classpath, but are
        // not scanned as application targets (ctx.targetClassesScan).
        Map<String, String> nativeLibraryNames = ctx.nativeLibraryNames;
        Map<String, String> classToJar = ctx.classToJarScan;
        List<SootClass> targetClasses = ctx.targetClassesScan;
        System.out.println("[DIRECTMAP] classes=" + targetClasses.size() + " out=" + out.getAbsolutePath());

        try (
                BufferedWriter hitW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(hitsFile), StandardCharsets.UTF_8));
                BufferedWriter skipW = new BufferedWriter(new OutputStreamWriter(
                        new FileOutputStream(skippedFile), StandardCharsets.UTF_8))
        ) {
            hitW.write("=== JNA Direct Mapping Hits ===\n");
            hitW.write("Format: methodSig | lib | symbol | apiPattern | jar\n\n");

            skipW.write("=== Skipped Methods (VerifyError/Exceptions) ===\n");
            skipW.write("Format: methodSig | exceptionType | message\n\n");

            long hits = 0;
            long skipped = 0;

            // ============================================================
            // PASS 0: Summarize helpers that return constant Strings, e.g.
            //   static String libName() { return "c"; }
            // Iterated to a fixed point so helpers calling helpers resolve too.
            // ============================================================
            System.out.println("[PASS 0] Summarizing string-return helper methods...");
            int iterations = 0;
            boolean changed = true;
            while (changed && iterations++ < MAX_SUMMARY_ITERATIONS) {
                changed = false;
                for (SootClass sc : targetClasses) {
                    for (SootMethod m : sc.getMethods()) {
                        String sig = m.getSignature().toString();
                        if (methodStringReturns.containsKey(sig)) continue;
                        try {
                            if (!m.hasBody()) continue;
                            String s = summarizeStringReturn(m);
                            if (s != null) {
                                methodStringReturns.put(sig, s);
                                changed = true;
                            }
                        } catch (VerifyError | RuntimeException e) {
                            // Logged in PASS 1, where the same method is visited again.
                            if (DEBUG) {
                                System.out.println("[DBG] PASS0 skip " + sig + ": " + e);
                            }
                        }
                    }
                }
            }
            System.out.println("[PASS 0] String helper summaries: " + methodStringReturns.size()
                    + " (in " + iterations + " iteration(s))");

            // ============================================================
            // PASS 1: Scan all method bodies for Native.register() calls.
            // Captures: static { Native.register("c"); }
            //      and: static { Native.register(NativeLibrary.getInstance("c", ...)); }
            //      and: Native.register(SomeClass.class, "c") in helper/init methods,
            //           attributed to SomeClass (the Class argument), not the caller.
            // ============================================================
            System.out.println("[PASS 1] Processing methods to find Native.register() calls...");

            long methodsScanned = 0;
            for (SootClass sc : targetClasses) {
                String className = sc.getType().getFullyQualifiedName();
                for (SootMethod m : sc.getMethods()) {
                    try {
                        if (!m.hasBody()) continue;
                        methodsScanned++;
                        for (Map.Entry<String, RegisterInfo> e : findRegisterCalls(m, className).entrySet()) {
                            recordRegistration(e.getKey(), e.getValue());
                        }
                    } catch (VerifyError e) {
                        skipped++;
                        skipW.write(m.getSignature() + " | VerifyError | " + e.getMessage() + "\n");
                    } catch (Exception e) {
                        skipped++;
                        skipW.write(m.getSignature() + " | " + e.getClass().getSimpleName()
                                + " | " + e.getMessage() + "\n");
                    }
                }
            }
            System.out.println("[PASS 1] Scanned " + methodsScanned + " methods");
            System.out.println("[PASS 1] Found " + classToReg.size() + " classes with Native.register()");

            // ============================================================
            // PASS 2: For each registered class, emit all native methods.
            // ============================================================
            System.out.println("[PASS 2] Collecting native methods from registered classes...");

            for (SootClass sc : targetClasses) {
                String className = sc.getType().getFullyQualifiedName();
                RegisterInfo regInfo = classToReg.get(className);
                if (regInfo == null) continue;

                String jarFile = classToJar.getOrDefault(className, "<?>");

                for (SootMethod m : sc.getMethods()) {
                    if (!m.isNative()) continue;

                    String methodSig = m.getSignature().toString();
                    String symbol = m.getName(); // JNA convention: symbol = method name

                    hits++;
                    String lib = NativeLibraryNames.resolve(regInfo.lib, nativeLibraryNames);
                    hitW.write(methodSig + " | " + lib + " | " + symbol + " | "
                            + regInfo.apiPattern + " | " + jarFile + "\n");

                    if (DEBUG) {
                        System.out.println("[DBG] HIT: " + methodSig + " | lib=" + regInfo.lib
                                + " | symbol=" + symbol + " | api=" + regInfo.apiPattern);
                    }
                }
            }

            System.out.println("[INFO] total JNA direct-mapped hits: " + hits);
            System.out.println("[INFO] skipped methods: " + skipped);
            System.out.println("[INFO] wrote hits    => " + hitsFile.getAbsolutePath());
            System.out.println("[INFO] wrote skipped => " + skippedFile.getAbsolutePath());
        }
    }

    /**
     * Records a registration, never letting an unresolved entry ("<?>")
     * overwrite a previously resolved library name.
     */
    private void recordRegistration(String className, RegisterInfo info) {
        RegisterInfo prev = classToReg.get(className);
        if (prev == null || (!prev.isResolved() && info.isResolved())) {
            classToReg.put(className, info);
            if (DEBUG) {
                System.out.println("[DBG] REGISTER: " + className + " -> lib=" + info.lib
                        + " api=" + info.apiPattern);
            }
        }
    }

    /**
     * Scans a method body for ALL calls to Native.register(...).
     *
     * Handles:
     *   - Native.register(String libName)
     *   - Native.register(Class, String libName)
     *   - Native.register(NativeLibrary)
     *   - Native.register(Class, NativeLibrary)
     *
     * Tracks string constants (directly assigned, copied between locals, or
     * returned by summarized helper methods), NativeLibrary.getInstance(...)
     * results, and class constants (for the Class-argument variants).
     *
     * @param method        the method to analyze
     * @param declaringClass FQCN of the method's declaring class; used as the
     *                      registered class for the no-Class-arg variants and
     *                      as fallback when the Class argument is not constant
     * @return map of registered class FQCN -> RegisterInfo (possibly empty)
     */
    private Map<String, RegisterInfo> findRegisterCalls(SootMethod method, String declaringClass) {
        Map<String, RegisterInfo> result = new HashMap<>();
        Map<Local, String> localToString = new HashMap<>();
        Map<Local, String> localToClassName = new HashMap<>();
        Map<Local, String> nativeLibraryToLib = new HashMap<>();

        for (Stmt stmt : method.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = as.getRightOp();

                if (lhs instanceof Local) {
                    Local lhsLocal = (Local) lhs;
                    // Invalidate stale facts: this local is being redefined.
                    localToString.remove(lhsLocal);
                    localToClassName.remove(lhsLocal);
                    nativeLibraryToLib.remove(lhsLocal);

                    if (rhs instanceof StringConstant) {
                        localToString.put(lhsLocal, ((StringConstant) rhs).getValue());
                    } else if (rhs instanceof ClassConstant) {
                        localToClassName.put(lhsLocal, classConstantToFqcn((ClassConstant) rhs));
                    } else if (rhs instanceof Local) {
                        // Propagate copies: a = b
                        Local rhsLocal = (Local) rhs;
                        copyIfPresent(localToString, rhsLocal, lhsLocal);
                        copyIfPresent(localToClassName, rhsLocal, lhsLocal);
                        copyIfPresent(nativeLibraryToLib, rhsLocal, lhsLocal);
                    } else if (rhs instanceof AbstractInvokeExpr) {
                        AbstractInvokeExpr inv = (AbstractInvokeExpr) rhs;
                        MethodSignature sig = inv.getMethodSignature();

                        // local = helperReturningConstantString()
                        String returnedString = methodStringReturns.get(sig.toString());
                        if (returnedString != null) {
                            localToString.put(lhsLocal, returnedString);
                        }

                        // local = NativeLibrary.getInstance(libName, ...)
                        if (JNA_NATIVE_LIBRARY.equals(sig.getDeclClassType().getFullyQualifiedName())
                                && "getInstance".equals(sig.getName())) {
                            String libName = resolveStringArg(inv, localToString, 0);
                            if (libName != null) {
                                nativeLibraryToLib.put(lhsLocal, libName);
                                if (DEBUG) {
                                    System.out.println("[DBG] NativeLibrary.getInstance: "
                                            + lhsLocal + " -> lib=" + libName);
                                }
                            }
                        }
                    }
                }
            }

            // Look for Native.register(...) invocations (do NOT stop at the
            // first one: a helper may register several classes).
            AbstractInvokeExpr inv = getInvoke(stmt);
            if (inv == null) continue;

            MethodSignature sig = inv.getMethodSignature();
            if (!JNA_NATIVE.equals(sig.getDeclClassType().getFullyQualifiedName())
                    || !"register".equals(sig.getName())) {
                continue;
            }

            List<Immediate> args = inv.getArgs();
            List<?> paramTypes = sig.getSubSignature().getParameterTypes();
            boolean hasClassParam = !paramTypes.isEmpty()
                    && "java.lang.Class".equals(paramTypes.get(0).toString());

            // Which class is being registered?
            String registeredClass = declaringClass;
            if (hasClassParam && !args.isEmpty()) {
                Immediate classArg = args.get(0);
                if (classArg instanceof ClassConstant) {
                    registeredClass = classConstantToFqcn((ClassConstant) classArg);
                } else if (classArg instanceof Local) {
                    String resolved = localToClassName.get(classArg);
                    if (resolved != null) registeredClass = resolved;
                    // else: non-constant Class arg; fall back to declaring class
                }
            }

            // Library name: String argument (patterns 1 & 2) ...
            RegisterInfo info = null;
            int libArgIdx = hasClassParam ? 1 : 0;
            String libFromString = resolveStringArg(inv, localToString, libArgIdx);
            if (libFromString != null) {
                info = new RegisterInfo(libFromString,
                        hasClassParam ? API_REGISTER_CLASS_STRING : API_REGISTER_STRING);
            } else {
                // ... or a NativeLibrary argument (patterns 3 & 4)
                for (Immediate arg : args) {
                    if (arg instanceof Local) {
                        String libName = nativeLibraryToLib.get(arg);
                        if (libName != null) {
                            info = new RegisterInfo(libName, hasClassParam
                                    ? API_REGISTER_CLASS_NATIVELIBRARY
                                    : API_REGISTER_NATIVELIBRARY);
                            break;
                        }
                    }
                }
            }

            if (info == null) {
                info = new RegisterInfo(UNRESOLVED_LIB, API_UNKNOWN);
            }
            // Keep the best info per registered class within this method too.
            RegisterInfo prev = result.get(registeredClass);
            if (prev == null || (!prev.isResolved() && info.isResolved())) {
                result.put(registeredClass, info);
            }
        }

        return result;
    }

    private static <V> void copyIfPresent(Map<Local, V> map, Local from, Local to) {
        V v = map.get(from);
        if (v != null) map.put(to, v);
    }

    /**
     * Converts a Jimple class constant value (e.g. "Lcom/foo/Bar;") to an FQCN.
     */
    private static String classConstantToFqcn(ClassConstant cc) {
        String v = cc.getValue();
        if (v.startsWith("L") && v.endsWith(";")) {
            v = v.substring(1, v.length() - 1);
        }
        return v.replace('/', '.');
    }

    /**
     * If the method always boils down to returning a single constant String
     * (directly, via a local, or via an already-summarized helper call),
     * returns that String; otherwise null.
     *
     * Note: returns the FIRST resolvable constant return. Methods with
     * multiple differing return values are summarized by whichever return
     * appears first in the statement list (a known, accepted imprecision).
     */
    private String summarizeStringReturn(SootMethod m) {
        Map<Local, String> localToString = new HashMap<>();

        for (Stmt stmt : m.getBody().getStmts()) {
            if (stmt instanceof JAssignStmt) {
                JAssignStmt as = (JAssignStmt) stmt;
                Value lhs = as.getLeftOp();
                Value rhs = as.getRightOp();

                if (lhs instanceof Local) {
                    Local lhsLocal = (Local) lhs;
                    localToString.remove(lhsLocal);
                    if (rhs instanceof StringConstant) {
                        localToString.put(lhsLocal, ((StringConstant) rhs).getValue());
                    } else if (rhs instanceof Local) {
                        copyIfPresent(localToString, (Local) rhs, lhsLocal);
                    } else if (rhs instanceof AbstractInvokeExpr) {
                        // Propagate summaries of helpers calling helpers
                        // (resolved across PASS 0 fixed-point iterations).
                        String s = methodStringReturns.get(
                                ((AbstractInvokeExpr) rhs).getMethodSignature().toString());
                        if (s != null) localToString.put(lhsLocal, s);
                    }
                }
            } else if (stmt instanceof JReturnStmt) {
                Value op = ((JReturnStmt) stmt).getOp();
                if (op instanceof StringConstant) {
                    return ((StringConstant) op).getValue();
                }
                if (op instanceof Local) {
                    String s = localToString.get(op);
                    if (s != null) return s;
                }
            }
        }
        return null;
    }
}
