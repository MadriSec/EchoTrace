# JNI Interface Detection (Bytecode + Toolchain)

This document describes how EchoTrace detects **JNI static** (`native` declarations in bytecode) and how that ties into **application-level** versus **JDK** native surfaces, **cross-JDK** regression tests, and downstream **symbol mapping**. It focuses on `PrototypeFinal` and the JUnit fixtures in `src/test/java/.../crossjdk/`.

For other native bridges (JNA, Panama, jnr-ffi), see [README.md in this package](./README.md).

---

## 1. Where JNI fits in the pipeline

| Stage | Artifact | Role |
|-------|----------|------|
| Bytecode scan | `native_methods.txt` | One line per `native` method the analyzer believes exists in loaded JARs (FQCN). |
| ELF / nm | `mapped_method_syscalls.txt` (via `mapped_updated.py`) | Resolves each line to `Java_*`, `JVM_*`, `RegisterNatives`, Netty patterns, etc. |
| Optional | `jni_dynamic_bindings.txt` | `extract_jni_bindings.py` — `JNINativeMethod[]` tables inside `.so` files. |
| Optional | `JDK<N>/jvm_native_bindings.txt` | `extract_jvm_native_tables.py` — HotSpot `JVM_*` / libjava registrations from **OpenJDK source**. |

**JNI static detection** does not need a running JVM. It only needs `.class` bytes (and, for call tracing, the same JDK **runtime** classes on a classloader that match the deployment you care about).

---

## 2. `PrototypeFinal` — static JNI from bytecode

**Source:** [`PrototypeFinal.java`](./PrototypeFinal.java)

### 2.1 Mode `--1` (ASM / “HybridByteCodeTracer”)

1. **Jar sweep** — For each JAR under the logical “target” list, open every `*.class` entry.
2. **ClassVisitor (`ClassPrinter`)** — For each method, check **`ACC_NATIVE` (0x100)**. If set, record `fully.qualified.Class.methodName` in `Util.visitedNative`.
3. **MethodVisitor (`MethodPrinter`)** — For each bytecode **`invoke`** (`INVOKEVIRTUAL`, `INVOKESTATIC`, …), resolve the callee’s `.class` via **`targetClassLoader.getResourceAsStream`**, recurse with a new `ClassReader`, and repeat steps 2–3.

So the analyzer discovers:

- **Direct natives** — Declared on classes in the JARs you asked it to scan.
- **Transitive natives** — Methods on JDK or library types **called from** scanned bytecode, **only if** the callee’s `.class` is visible on `targetClassLoader`.

### 2.2 `--runtime DIR` (and `PROTOTYPE_RUNTIME_DIR`)

JARs under **`--runtime`** are placed on the **`URLClassLoader`** but are **not** enumerated as primary scan roots in the same way as the main jar directory — the intent is to supply **`java.base`** (or a full modular runtime repacked as flat JARs) so **Flow 2** can open `java.lang.Object`, `java.io.*`, etc., when your app calls into the JDK.

**Why it matters:** If you omit `--runtime`, you may still see all **app** `native` declarations, but you may **miss** JDK `native` methods that appear only through invoked callees. For seccomp / syscall workflows you usually want parity with the **container’s JDK**.

### 2.3 Output

- Default file name: `native_methods.txt` (path also influenced by `-Dprototype.output.dir` and directory naming conventions documented in `PrototypeFinal`’s class Javadoc).

---

## 3. Application-level JNI vs JDK JNI

| Category | Typical bytecode location | Typical ELF home | Mapping strategy |
|----------|--------------------------|------------------|------------------|
| **Application / dependency** | `com.myapp.*`, `org.apache.hadoop.*`, Netty, Tomcat native, … | App or vendor `.so` (`libfoo.so`, `libnetty_*.so`, …) | `nm` **`Java_*`**; **`extract_jni_bindings.py`** for `RegisterNatives`; Netty-specific fallbacks in `mapped_updated.py`. |
| **JDK / JVM** | `java.*`, `jdk.*`, `sun.*` (legacy) | **`libjvm.so`**, **`libjava.so`**, **`libzip.so`**, … | **`JVM_*`** from **`extract_jvm_native_tables.py`** intersected with **`nm libjvm.so`**; **JNI** names like **`Java_java_util_zip_Inflater_*`** from global symbol scan. |

**Version sensitivity**

- The **same FQ method** can be `native` in one JDK and rewritten in Java or turned into an **intrinsic** in another (e.g. Loom changes around **`Thread`** APIs).
- **`libzip`** JNI symbols evolved: bytecode may reference **`inflateBytesBytes`** / **`deflateBufferBytes`** while older runtimes exported shorter `Java_*` names — `mapped_updated.py` therefore tries **multiple JNI lookup keys** (variant + original name).

- **Class file major version** (e.g. **69** = Java **25**) must be parsable by **ASM** on your classpath; older ASM throws **`Unsupported class file major version`** when analyzing Tomcat or dependencies built for newer releases.

---

## 4. Automated cross-JDK test cases

All tests use **`Assumptions`** when a JDK artifact is missing — they **skip**, not fail, so laptops without every JDK still get a green build.

### 4.1 Fixture resolution — `CrossJdkTestFixtures`

**Location:** `src/test/java/com/echotrace/app/bytecode_new/crossjdk/CrossJdkTestFixtures.java`

For each JDK era the fixture searches, in order:

1. JVM system properties (`echotrace.jdk*.…`)
2. Environment variables (`ECHOTRACE_JDK8_RT_JAR`, `ECHOTRACE_JDK9_JAVA_BASE_JMOD`, `ECHOTRACE_JDK11_JAVA_BASE_JMOD`, `ECHOTRACE_JDK15_JAVA_BASE_JMOD`, `ECHOTRACE_JDK21_JAVA_BASE_JMOD`, `ECHOTRACE_JDK25_JAVA_BASE_JMOD`, …)
3. Common Linux paths (`/usr/lib/jvm/...`)
4. Repo-relative **`JDKs/`** (e.g. `JDKs/jdk-11.0.31+11/jmods/java.base.jmod`, `JDKs/jdk-25.0.3+9/jmods/java.base.jmod`)
5. **`/tmp/jdks_for_test/*.jmod`** produced by **`scripts/fetch_test_jdks.sh`**

**Staging:** `java.base.jmod` (or another `*.jmod`) is repacked into a **flat JAR** (strip the `classes/` prefix) so `JarFile` + ASM see normal entries like `java/lang/Object.class`.

### 4.2 `PrototypeFinalCrossJdkCoverageTest`

**What it does**

- For **each** resolved JDK (labels such as **`JDK 8 (rt.jar)`**, **`JDK 25 (java.base.jmod)`**, …):
  - Stages one flat runtime JAR.
  - Builds a **`URLClassLoader`** with that JAR only (same pattern as `PrototypeFinal` production use).
  - Runs **`traceJarFiles`** on that single JAR — effectively walking **all** `java.base` classes (modular JDK) or the full **rt.jar** surface (JDK 8).

**Assertions**

1. **Count floor** — At least **50** `native` entries (sanity against empty walks).
2. **Stable natives** — The following must appear in **`visitedNative`** for every JDK that runs the test body:
   - `java.lang.Object.hashCode`
   - `java.lang.Object.notify`
   - `java.lang.Object.notifyAll`
   - `java.lang.Object.clone`
   - `java.lang.Thread.start0`  
   (These are chosen because they stayed **`ACC_NATIVE` across the versions we target;** Loom famously moved **`Thread.yield`** / **`sleep`** off the public native API — such cases illustrate *why* the **`@AfterAll` diff report** exists, not because they are asserted here.)
3. **Package richness** — At least **20** methods under `java.lang.*`.

**Results / console output (what to expect)**

When multiple JDKs are present, the test prints:

1. **Per-JDK banner** — Total natives, counts for `java.lang.*`, `java.io.*`, `java.nio.*`, `jdk.internal.*`, `sun.*`.
2. **`@AfterAll` summary** — `=== Cross-JDK native-method coverage ===` with one line per JDK label and **total native count**.
3. **Evolution report** — `=== Per-version evolution (added vs. dropped) ===` — for each adjacent pair in run order, up to **8** sample **`+`** / **`-`** FQ method names.

**Interpretation**

- **JDK 8** totals are **much larger** than **JDK 9+ java.base-only** totals — `rt.jar` bundles more than one module’s worth of packages.
- **Added** / **dropped** lines are **not** bugs by themselves; they reflect **platform**, **security**, and **Project Loom** refactors. They *are* early warning if your **`PrototypeFinal`** walk suddenly collapses (e.g. zero `java.lang.Object.hashCode`).

**Example: same API, `native` in one JDK and not in another**

Project Loom (**JDK 19+**) rewrote parts of **`java.lang.Thread`** so the **public** methods are ordinary Java that call **private** natives — the bytecode **`ACC_NATIVE` flag** moves off the historic names. Contrast:

| Method (FQJN) | Typical JDK **8 – 18** (`java.base` bytecode) | JDK **19+** (Loom-style `java.base`) |
|-----------------|-----------------------------------------------|--------------------------------------|
| `java.lang.Thread.yield` | Declared **`native`** (`yield`) | **Not** `native` on the public method; implementation delegates to private natives (e.g. `yield0` / VM support) |
| `java.lang.Thread.sleep(long)` / overloads | Public **`native sleep`** in older releases | Same story: public **`sleep`** is Java; work is routed through **virtual-thread** / carrier **scheduling** and **private** `native` helpers |

So a **`native_methods.txt`** line (or absence of one) for **`java.lang.Thread.yield`** can **change** when you switch the staged **`RUNTIME_*`** from JDK 11 to JDK 21 — not because EchoTrace is wrong, but because the **class file** really changed. That is why the cross-JDK test prints **dropped** entries and why seccomp pipelines must pair analysis with the **same major** the container runs.

*Example shape (numbers depend on your exact JDK builds):*

```text
[JDK 11 (java.base.jmod)]
  total natives:        847
  java.lang.*:          91
  ...

=== Cross-JDK native-method coverage ===
  JDK 8  (rt.jar)                2543 native methods
  JDK 11 (java.base.jmod)         847 native methods
  JDK 25 (java.base.jmod)         892 native methods

=== Per-version evolution (added vs. dropped) ===
  JDK 8  (rt.jar) -> JDK 11 (java.base.jmod)
    added (12) — illustrative `native` entries tied to **JDK 9+ `java.base`** (checked in OpenJDK 17
      `java.base`; types like `java.lang.Module`, `VarHandle`, and `ProcessHandleImpl` did not exist in JDK 8):
      + java.lang.Module.defineModule0
      + java.lang.Module.addReads0
      + java.lang.Module.addExports0
      + java.lang.Module.addExportsToAll0
      + java.lang.Module.addExportsToAllUnnamed0
      + java.lang.invoke.VarHandle.get                  (signature-polymorphic accessor)
      + java.lang.invoke.VarHandle.set
      + java.lang.ProcessHandleImpl.initNative
      + java.lang.ProcessHandleImpl.getCurrentPid0
      + java.lang.ProcessHandleImpl.waitForProcessExit0
      + jdk.internal.loader.NativeLibraries.load
      + jdk.internal.loader.NativeLibraries.unload
      ...
    dropped (1804) — mostly **`rt.jar` outside `java.base`**; **AWT / desktop** natives (still shipped, but under **`java.desktop`**):
      - java.awt.Component.initIDs
      - java.awt.Toolkit.initIDs
      - java.awt.Font.initIDs
      - java.awt.Color.initIDs
      - java.awt.Window.initIDs
      - java.awt.Container.initIDs
      - java.awt.Frame.initIDs
      - java.awt.image.BufferedImage.initIDs
      - java.awt.event.KeyEvent.initIDs
      - java.awt.Cursor.initIDs
      - java.awt.Dialog.initIDs
      ...
    (`java.applet.*`, **`javax.swing.*`**, **`java.sql.*`**, … also disappear from a **`java.base`-only**
     scan because those modules split out; many of those types are **not** `native` at all. Fence helpers
     like **`VarHandle.acquireFence`** are **Java** in current OpenJDK sources, not **ACC_NATIVE**.)
    (Many drops are **not** “removed from the JDK” — the same packages moved to **java.desktop**,
     **java.sql**, **java.logging**, … and disappear from a **java.base-only** scan.)
  JDK 11 (java.base.jmod) -> JDK 21 (java.base.jmod)
    added (examples — **Vector API** and other **`jdk.internal.vm.*`** growth; exact list depends on the two builds):
      + jdk.internal.vm.vector.VectorSupport.getMaxLaneCount
      + jdk.internal.vm.vector.VectorSupport.registerNatives
      ...
    dropped (examples — **Project Loom** (JDK 19+) often rewrites **`java.lang.Thread`**: `yield` / `sleep`
      **lose `ACC_NATIVE` on the public methods** and delegate to new scheduler natives; compare your two `Thread.class` files):
      - java.lang.Thread.yield                         (often non-`native` **public** bytecode in 21+)
      - java.lang.Thread.sleep                         (`long` overload; public **Java** façade in 21+)
      ...
    (Exact FQNs vary by vendor tag; use the diff as a sanity signal, not a golden file.)
```

### 4.3 `PrototypeFinalCrossJdkAppAndRuntimeTest`

**Supporting class:** `DemoNativeApplication`

- **`public static native void applicationPing();`** — Pure **application-level** JNI (no implementation in tests; only the declaration matters for bytecode).
- **`touchJdkNative()`** — `new Object().hashCode();` to force resolution of **`java.lang.Object`** from the **staged runtime** (stable **`ACC_NATIVE`** across 8–25).

**What it does**

- Builds **`app-demo.jar`** containing only `DemoNativeApplication.class`.
- Stages **`java.base`** / **`rt.jar`** for the same JDK row as the parameterized test.
- **`URLClassLoader`** URL order: **[`app-demo.jar`, `runtime.jar`]** so app classes load first, JDK second.
- Sets **`PrototypeFinal`’s** static **`pathPrefix`** and **`targetClassLoader`** via reflection (same technique as the coverage test).
- Runs **`traceJarFiles(List.of("app-demo.jar"))`**.

**Assertions**

1. `com.echotrace.app.bytecode_new.crossjdk.DemoNativeApplication.applicationPing` ∈ `visitedNative`.
2. `java.lang.Object.hashCode` ∈ `visitedNative`.

**Results**

- If both assertions pass for a given JDK label, you have shown **end.to-end**: **app JAR scan + Flow 2 reach into the paired JDK** for that runtime artifact.
- If the first passes but the second fails, **`Object.class`** was not loadable from the staged runtime or Flow 2 did not walk `touchJdkNative()` (regression in `MethodPrinter` / classloader wiring).

---

## 5. How to run everything locally

```bash
# Optional: pull java.base.jmod for JDK 9 / 15 / 21 into /tmp/jdks_for_test/
./scripts/fetch_test_jdks.sh

# Run only the JNI / PrototypeFinal cross-JDK tests
mvn test -Dtest=PrototypeFinalCrossJdkCoverageTest,PrototypeFinalCrossJdkAppAndRuntimeTest
```

To **force** a JDK location:

```bash
export ECHOTRACE_JDK25_JAVA_BASE_JMOD=/home/you/jdk-25/jmods/java.base.jmod
mvn test -Dtest=PrototypeFinalCrossJdkAppAndRuntimeTest
```

---

## 6. Related files (quick index)

| File | Purpose |
|------|---------|
| [`PrototypeFinal.java`](./PrototypeFinal.java) | ASM native scan + invoke tracing; `--runtime` handling. |
| [`README.md`](./README.md) | All native bridges (JNI, JNA, Panama, …). |
| `src/test/.../crossjdk/CrossJdkTestFixtures.java` | Path resolution + jmod→jar staging. |
| `src/test/.../crossjdk/DemoNativeApplication.java` | Minimal app + JDK callee for app+runtime test. |
| `src/test/.../PrototypeFinalCrossJdkCoverageTest.java` | Whole-module native inventory + diff report. |
| `src/test/.../PrototypeFinalCrossJdkAppAndRuntimeTest.java` | App JAR + versioned runtime pairing. |
| `scripts/fetch_test_jdks.sh` | Docker-based `java.base.jmod` fetch for CI/dev without full local JDK matrix. |
| Repo root `mapped_updated.py` | Post-process `native_methods.txt` → libraries / `JNI` / `JVM` tags. |
| `extract_jvm_native_tables.py` | OpenJDK **source** scan → `jvm_native_bindings.txt` per major version. |
| `extract_jni_bindings.py` | ELF scan → dynamic `RegisterNatives` bindings. |

---

## 7. Summary

- **JNI static detection** = **`ACC_NATIVE` in bytecode**, implemented primarily by **`PrototypeFinal`** Mode `--1` using **ASM**, with optional **JDK runtime** classes on the loader via **`--runtime`**.
- **Tests** prove (1) **coverage across JDK versions** when artifacts exist and (2) **app + JDK pairing** via **`DemoNativeApplication`**.
- **Downstream**, EchoTrace splits **application** vs **JDK** resolution: **`Java_*` / dynamic JNI** vs **`JVM_*` / libjvm**, and hardens for **JDK evolution** (symbol naming, Loom, new bytecode levels).
