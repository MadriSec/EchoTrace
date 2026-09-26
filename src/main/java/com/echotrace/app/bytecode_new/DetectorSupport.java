package com.echotrace.app.bytecode_new;

import sootup.core.IdentifierFactory;
import sootup.core.jimple.basic.Immediate;
import sootup.core.jimple.basic.Local;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.constant.StringConstant;
import sootup.core.jimple.common.expr.AbstractInstanceInvokeExpr;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.expr.JCastExpr;
import sootup.core.jimple.common.ref.JFieldRef;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.JInvokeStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.model.SootClass;
import sootup.java.core.views.JavaView;

import java.io.BufferedWriter;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Shared helpers for the JNA/FFI detector family
 * (JnaDirectMapDetector, JnaIfaceDetector, JnaDynDetector, FfiDetector).
 *
 * Centralizing these removes ~150 duplicated lines per detector and
 * guarantees they all behave identically (same jar scanning, same Jimple
 * unwrapping, same field keying).
 */
final class DetectorSupport {

    private DetectorSupport() {}

    /** Enable debug logging with -Ddetector.debug=true */
    static final boolean DEBUG = Boolean.getBoolean("detector.debug");

    // ------------------- CLI / output helpers -------------------

    /** JARFILES_&lt;image&gt; -> outputs_&lt;image&gt;, else outputs_&lt;dirname&gt;. */
    static String deriveDefaultOutDir(String targetDir) {
        String dirName = new File(targetDir).getName();
        return dirName.startsWith("JARFILES_")
                ? "outputs_" + dirName.substring("JARFILES_".length())
                : "outputs_" + dirName;
    }

    /** Skip-log line: methodSig | exceptionType | message (newlines stripped). */
    static void writeSkip(BufferedWriter w, String methodSig, Throwable t) throws IOException {
        String msg = (t.getMessage() == null) ? ""
                : t.getMessage().replace('\n', ' ').replace('\r', ' ');
        w.write(methodSig + " | " + t.getClass().getName() + " | " + msg + "\n");
        if (DEBUG) {
            System.err.println("[SKIPPED] " + methodSig + " :: " + t.getClass().getSimpleName() + " " + msg);
        }
    }

    // ------------------- Jar scanning -------------------

    /** Recursively collects all JAR file paths from a directory (iterative). */
    static List<String> collectJarPaths(String dirPath) {
        List<String> jars = new ArrayList<>();
        File root = new File(dirPath);

        if (!root.isDirectory()) {
            System.err.println("[WARN] not a directory: " + dirPath);
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

    /**
     * Maps each class FQCN to its source JAR basename (single scan — use
     * keySet() when only the names are needed). Warns on classpath shadowing.
     */
    static Map<String, String> collectClassToJar(List<String> jarPaths) {
        Map<String, String> classToJar = new HashMap<>();
        int duplicates = 0;
        for (String jar : jarPaths) {
            String jarName = new File(jar).getName();
            try (ZipFile zf = new ZipFile(jar)) {
                Enumeration<? extends ZipEntry> en = zf.entries();
                while (en.hasMoreElements()) {
                    ZipEntry e = en.nextElement();
                    String name = e.getName();
                    if (name.endsWith(".class") && !name.contains("module-info")) {
                        String cls = name.substring(0, name.length() - 6).replace('/', '.');
                        String prev = classToJar.put(cls, jarName);
                        if (prev != null && !prev.equals(jarName)) duplicates++;
                    }
                }
            } catch (Exception ex) {
                System.err.println("[WARN] failed reading jar: " + jar + " :: " + ex.getMessage());
            }
        }
        if (duplicates > 0) {
            System.out.println("[WARN] " + duplicates
                    + " class(es) shadowed across multiple jars; attribution uses the last jar seen");
        }
        return classToJar;
    }

    /** Jars that are framework/runtime code, excluded from target scans. */
    static boolean isFrameworkRuntimeJar(String jarPath) {
        String name = new File(jarPath).getName().toLowerCase(Locale.ROOT);
        return name.startsWith("jna-")
                || name.startsWith("jnr-")
                || name.startsWith("jffi-")
                || name.startsWith("hawtjni-runtime-");
    }

    static List<String> targetScanJars(List<String> jars) {
        return jars.stream()
                .filter(jar -> !isFrameworkRuntimeJar(jar))
                .collect(Collectors.toList());
    }

    /** Joins paths with the platform path separator. */
    static String toClassPath(List<String> entries) {
        return String.join(File.pathSeparator, entries);
    }

    /** Target jars + optional -Ddetector.runtime.dir jars for the analysis classpath. */
    static List<String> analysisClasspathJars(List<String> targetJars) {
        List<String> jars = new ArrayList<>(targetJars);
        String runtimeDir = System.getProperty("detector.runtime.dir");
        if (runtimeDir != null && !runtimeDir.trim().isEmpty()) {
            List<String> runtimeJars = collectJarPaths(runtimeDir.trim());
            jars.addAll(runtimeJars);
            System.out.println("[INFO] detector.runtime.dir jars: " + runtimeJars.size());
        }
        return jars;
    }

    // ------------------- View helpers -------------------

    /**
     * Resolves exactly the named classes (lazy, classpath-ordered) instead of
     * enumerating the whole view. Unresolvable names are reported via stderr.
     */
    static List<SootClass> resolveTargetClasses(JavaView view, Collection<String> fqcns) {
        List<SootClass> out = new ArrayList<>(fqcns.size());
        IdentifierFactory idf = view.getIdentifierFactory();
        for (String fqcn : fqcns) {
            try {
                view.getClass(idf.getClassType(fqcn)).ifPresent(out::add);
            } catch (Exception e) {
                System.err.println("[WARN] failed resolving class: " + fqcn + " :: " + e.getMessage());
            }
        }
        return out;
    }

    /**
     * Sorts outer classes (no '$') before inner classes, so outer &lt;clinit&gt;
     * taints are usually available when inner classes are processed.
     */
    static void sortOuterClassesFirst(List<SootClass> classes) {
        classes.sort((a, b) -> {
            String an = a.getType().getFullyQualifiedName();
            String bn = b.getType().getFullyQualifiedName();
            boolean aInner = an.contains("$");
            boolean bInner = bn.contains("$");
            if (aInner != bInner) return aInner ? 1 : -1;
            return an.compareTo(bn);
        });
    }

    // ------------------- Jimple helpers -------------------

    static AbstractInvokeExpr asInvoke(Value v) {
        return (v instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) v : null;
    }

    /**
     * Extracts the invoke expression from a statement (JInvokeStmt or
     * JAssignStmt, through casts). Defensively unwraps Optional for SootUp
     * versions where getInvokeExpr() returns Optional&lt;...&gt;.
     */
    static AbstractInvokeExpr getInvoke(Stmt stmt) {
        if (stmt instanceof JInvokeStmt) {
            Object ie = ((JInvokeStmt) stmt).getInvokeExpr();
            if (ie instanceof AbstractInvokeExpr) return (AbstractInvokeExpr) ie;
            if (ie instanceof Optional) {
                Object val = ((Optional<?>) ie).orElse(null);
                return (val instanceof AbstractInvokeExpr) ? (AbstractInvokeExpr) val : null;
            }
        } else if (stmt instanceof JAssignStmt) {
            return asInvoke(unwrapCasts(((JAssignStmt) stmt).getRightOp()));
        }
        return null;
    }

    /** Unwraps (possibly nested) cast expressions. */
    static Value unwrapCasts(Value v) {
        Value cur = v;
        while (cur instanceof JCastExpr) {
            cur = ((JCastExpr) cur).getOp();
        }
        return cur;
    }

    /**
     * Stable key for a field reference: the FIELD SIGNATURE only (raw
     * toString() would embed the receiver local name of instance refs,
     * breaking cross-method lookups).
     */
    static String fieldKey(JFieldRef fieldRef) {
        return fieldRef.getFieldSignature().toString();
    }

    /** Receiver local of an instance invoke; null for static invokes. */
    static Local getInvokeBaseLocal(AbstractInvokeExpr inv) {
        if (inv instanceof AbstractInstanceInvokeExpr) {
            Value base = ((AbstractInstanceInvokeExpr) inv).getBase();
            if (base instanceof Local) return (Local) base;
        }
        return null;
    }

    /**
     * Resolves args[idx] to a String: direct StringConstant first, then a
     * local tracked in localToString.
     */
    static String resolveStringArg(AbstractInvokeExpr inv, Map<Local, String> localToString, int argIndex) {
        List<Immediate> args = inv.getArgs();
        if (args.size() <= argIndex) return null;
        Immediate arg = args.get(argIndex);
        if (arg instanceof StringConstant) return ((StringConstant) arg).getValue();
        if (arg instanceof Local) return localToString.get(arg);
        return null;
    }
}
