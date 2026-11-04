# Native Method Detection

This directory contains EchoTrace's bytecode analysis detectors. Each detector targets a different mechanism by which Java code invokes native (C/C++) functions.

For a **deep dive on JNI static detection**, **`PrototypeFinal`**, **application vs JDK natives**, and **cross-JDK JUnit results**, see **[JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md)**. For `RegisterNatives` table recovery, see **[JNI Dynamic Binding.md](./JNI%20Dynamic%20Binding.md)**.

## Overview

Java applications reach native code through several interfaces. Each has a distinct bytecode signature that requires a specialized detection strategy:

| Type | Detector | What it finds |
|------|----------|---------------|
| JNI Static | `PrototypeFinal` | `native` keyword declarations |
| JNI Dynamic | *(no bytecode detector)* `scripts/extract_jni_bindings.py`, `scripts/extract_registernatives_binary.py` | `JNINativeMethod[]` tables registered via `RegisterNatives()` |
| JNA Interface Mapping | `JnaIfaceDetector` | Calls to interfaces extending `com.sun.jna.Library` |
| JNA Dynamic | `JnaDynDetector` | `NativeLibrary.getInstance().getFunction()` -> `Function.invoke*()` |
| JNA Direct Mapping | `JnaDirectMapDetector` | Classes calling `Native.register()` |
| Panama FFI | `FfiDetector` | `java.lang.foreign` / `jdk.incubator.foreign` downcalls |
| jnr-ffi | `JnrFfiDetector` | `LibraryLoader.create().load()` / `Library.loadLibrary()` |

`JNADetector` is the entry point the pipeline uses: it runs the five JNA/FFI/jnr-ffi detectors over one shared SootUp view, merges their hits, then runs `PrototypeFinal` in Mode 1.

---

## 1. JNI Static Binding

**File:** `PrototypeFinal.java`

**Java pattern:**

```java
public class System {
    public static native long nanoTime();
}
```

**How we detect it:**

`PrototypeFinal` has two modes:

- **Mode 1 (`--1`, used by the pipeline):** ASM scan of every `.class` in the JARs under the target directory. Any method with the `ACC_NATIVE` flag is a native method. Runtime JARs passed with `--runtime` (or `PROTOTYPE_RUNTIME_DIR`) are only placed on the class loader; they are not scanned wholesale, so a JDK native is reported only when an invoke chain from the application reaches it.
- **Mode 2 (`--2`, the CLI default):** SootUp worklist over Jimple IR, starting from the target JARs and following calls into a dependencies directory. Requires `<dependencies-directory>` as a second positional argument.

**Symbol naming convention:**
The JVM resolves these automatically to `Java_<package>_<Class>_<method>`:

```
java.lang.System.nanoTime  →  Java_java_lang_System_nanoTime (in libjava.so)
```

**Output:**

- Mode 1: `native_methods.txt`
- Mode 2: `sootup_visitor_natives.txt`

Both land in `outputs_<IMG_NAME>/` when the target directory is `JARFILES_<IMG_NAME>`; override with `-Dprototype.output.dir=<path>`.

**Limitations:** None for detection. The method is always visible in bytecode. The harder problem is *mapping* the method to a library (done downstream by `scripts/mapped_updated.py`).

---

## 2. JNI Dynamic Binding (RegisterNatives)

**Files:** `scripts/extract_jni_bindings.py`, `scripts/extract_registernatives_binary.py` (both invoked automatically by `scripts/mapped_updated.py`)

There is no bytecode detector for this case: a dynamically registered method looks like any other `native` declaration in bytecode and is already reported by `PrototypeFinal`. What is missing is the C symbol, which only the `.so` knows.

**C pattern (inside `.so`):**

```c
static JNINativeMethod methods[] = {
    {"beginRecording", "()V", (void*)jfr_begin_recording},
    {"isRecording",    "()Z", (void*)jfr_is_recording},
};

JNIEXPORT jint JNI_OnLoad(JavaVM *vm, void *reserved) {
    (*env)->RegisterNatives(env, cls, methods, 2);
}
```

**How we recover it:**

- **`extract_jni_bindings.py`** (third-party JNI: Netty, tcnative, jffi, ...):
  1. Qualify: the library must export `JNI_OnLoad` and match the host architecture
  2. Locate: group `R_*_RELATIVE` relocations into RELRO sections by 24-byte stride (one `{name, sig, fnPtr}` triple)
  3. Validate: `name` must be a Java identifier, `sig` a JNI signature, `fnPtr` an address in `.text` that resolves to a symbol
  4. Derive the Java class from the C symbol prefix; confidence is `HIGH_CONF` when a matching JNI class path string exists in `.rodata`, otherwise `SYM_INFER`
  - Output: `jni_dynamic_bindings.txt` (`<lib>|<JavaFQN>|<signature>|<C_symbol>|<confidence>`) and `jni_dynamic_summary.txt`
- **`extract_registernatives_binary.py`** (JDK libraries such as `libjvm.so`, `libjava.so`): disassembles each exported `*_registerNatives` function, reads the array address (`LEA` into `%rdx`) and count (`MOV` into `%ecx`), then decodes the 24-byte entries.
  - Output: `jvm_dynamic_mapping.txt`

`scripts/jfr_registernative_mapping.sh` is a standalone helper for the JFR table in `libjvm.so`; the pipeline does not call it.

**Limitations:** Tables built at runtime (e.g. `malloc`'d arrays) and non-PIC libraries without `R_*_RELATIVE` relocations are not recovered.

---

## 3. JNA Interface Mapping

**File:** `JnaIfaceDetector.java`

**Java pattern:**

```java
public interface CLib extends Library {
    CLib INSTANCE = Native.load("c", CLib.class);
    int strlen(String s);
    int getpid();
}

// Usage:
CLib.INSTANCE.strlen("hello");
```

**How we detect it:**

1. **Interface discovery:** Find all interfaces whose hierarchy includes `com.sun.jna.Library` (BFS through `StdCallLibrary`, `ALTLibrary` and custom intermediates)
2. **PASS 1 (taint, fixed point):** Track `Native.load(...)` / `Native.loadLibrary(...)` return values through locals, fields, synthetic accessors and helper methods that return the proxy, recording the library name from the string argument
3. **PASS 2 (call sites):** Report every call on a tainted proxy to a method of a JNA `Library` interface. The method name IS the native symbol name (JNA convention)

**Taint tracking:**

- Tracks the `Native.load()` result through field assignments (`INSTANCE = Native.load(...)`)
- Handles `Native.synchronizedLibrary(...)` wrappers
- Handles conditional library names (`Platform.isWindows() ? "msvcrt" : "c"`)
- Skips Windows/macOS/Solaris-only packages and libraries (`win32`, `kernel32`, `CoreFoundation`, ...), which are irrelevant in a Linux container

**Output:** `jna_iface_hits.txt`

```
Format: callerSig | lib | symbol | apiPattern | interface | calleeSig | callerJar | calleeJar
```

**Limitations:** If the library name is computed at runtime (not a string constant), `lib` is `<?>`.

---

## 4. JNA Dynamic Use

**File:** `JnaDynDetector.java`

**Java pattern:**

```java
NativeLibrary lib = NativeLibrary.getInstance("c");
Function fn = lib.getFunction("mmap");
fn.invoke(int.class, new Object[]{addr, length, prot, flags, fd, offset});
```

**How we detect it:**

1. **PASS 1 (taint, fixed point):** Track `NativeLibrary.getInstance("libname")` and `.getFunction("symbolName")` results through locals, fields and helper-method return summaries
2. **PASS 2 (invoke detection):** Detect `Function.invoke*()` calls and resolve the receiver back to its library and symbol

Classes under `com.sun.jna.*` are analysed (their field taints matter) but their hits are dropped, since they are JNA framework code rather than application calls.

**API variants detected:**

- `NativeLibrary.getFunction(String)` on a `NativeLibrary.getInstance(String)` result
- `Function.getFunction(String, String)` and its `int` / `int, String` overloads -> lib + symbol directly
- `Function.getFunction(Pointer)` / `(Pointer, int)` -> **unresolvable** (raw pointer, e.g. COM vtable)

**Output:** `jna_dyn_hits.txt`

```
Format: callerSig | lib | symbol | apiPattern | sinkSig | stmt
```

**Limitations:**

- `Function.getFunction(Pointer)` with a runtime pointer — `lib` and `symbol` are `<?>` because the pointer doesn't reveal the function name
- Dynamically computed library/symbol names

---

## 5. JNA Direct Mapping

**File:** `JnaDirectMapDetector.java`

**Java pattern:**

```java
public class CLibrary {
    static {
        Native.register("c");  // binds ALL native methods in this class to "c"
    }
    public static native int strlen(String s);
    public static native int getpid();
}
```

**How we detect it:**

1. **PASS 1:** Find calls to `Native.register(String)`, `Native.register(Class, String)`, `Native.register(NativeLibrary)` or `Native.register(Class, NativeLibrary)` and extract the library name (including through `NativeLibrary.getInstance("c", ...)` and string-returning helpers). For the `Class` overloads, the registered class is the `Class` argument, not the class containing the call
2. **PASS 2:** For each registered class, enumerate all methods with the `ACC_NATIVE` modifier — each method name IS the C symbol (JNA direct-mapping convention)

**Key difference from Interface Mapping:** Direct mapping uses `native` method declarations (like JNI) but resolves them at class-load time via JNA's runtime registration, not the JVM's standard `Java_*` symbol lookup.

**Output:** `jna_directmap_hits.txt`

```
Format: methodSig | lib | symbol | apiPattern | jar
```

**Limitations:** If the library name is computed at runtime, `lib` is `<?>`.

---

## 6. Panama FFI (Foreign Function & Memory API)

**File:** `FfiDetector.java`

**Java pattern (Java 22+ finalized API):**

```java
SymbolLookup lookup = SymbolLookup.libraryLookup("ssl", arena);
MemorySegment addr = lookup.find("SSL_read").orElseThrow();
MethodHandle handle = Linker.nativeLinker().downcallHandle(addr, descriptor);
int result = (int) handle.invokeExact(ssl, buf, len);
```

**Java pattern (Java 17-21 incubator API):**

```java
LibraryLookup lookup = LibraryLookup.ofLibrary("ssl");
MemoryAddress addr = lookup.lookup("SSL_read").get();
MethodHandle handle = CLinker.getInstance().downcallHandle(addr, methodType, descriptor);
```

**How we detect it:**

1. **PASS 1 (library discovery):** Track `SymbolLookup.libraryLookup(...)`, `LibraryLookup.ofLibrary(...)` / `ofPath(...)`, `loaderLookup()` and `defaultLookup()` — extract the library name via string constant
2. **PASS 1 (symbol resolution):** Track `.find("symbol")` / `.lookup("symbol")` calls — extract the symbol name
3. **PASS 1 (handle binding):** Track `downcallHandle(addr, ...)` — connect the handle to the resolved symbol
4. **PASS 2 (invoke detection):** Detect `MethodHandle.invokeExact(...)` / `invoke(...)` and resolve the receiver back to library + symbol

When a sibling `LIBS_*` directory exists, its `nm -D` symbols are indexed so callback/holder symbols can be attributed to a library.

**Both API generations detected:**

- `java.lang.foreign.*` (Java 22+ finalized)
- `jdk.incubator.foreign.*` (Java 17-21 incubator)

**Output:** `ffi_hits.txt`

```
Format: callerSig | lib | symbol | mechanism | jar
```

Example (Tomcat's FFM OpenSSL layer):

```
<org.apache.tomcat.util.openssl.openssl_h: int SSL_do_handshake(java.lang.foreign.MemorySegment)> | ssl | SSL_do_handshake | downcallHandle | tomcat-coyote-ffm.jar
```

**Limitations:**

- `defaultLookup()` (and the incubator `ofDefault()` / `CLinker.getInstance()`) resolves from the default C library — `lib` is `<default-c-lib>`; `loaderLookup()` gives `<loader>`
- If the library or symbol name is computed at runtime, it is `<?>`

---

## 7. jnr-ffi (JRuby Native Runtime)

**File:** `JnrFfiDetector.java`

**Java pattern:**

```java
public interface LibC {
    int getpid();
    int kill(int pid, int signal);
}

LibC libc = LibraryLoader.create(LibC.class)
    .library("c")
    .load();
libc.getpid();
```

**How we detect it:**

1. **PASS 1:** Scan `<clinit>` for `LibraryLoader.create(Interface.class).library("libname").load()` chains and `Library.loadLibrary(...)` calls — build interface -> library mappings
2. **PASS 2:** Report call sites to methods of the discovered interfaces. The method name IS the C symbol (same convention as JNA)

**API variants:**

- `LibraryLoader.create(I.class).library("c").load()` — chained builder
- `LibraryLoader.create(I.class).load("c")` — direct string
- `Library.loadLibrary("c", I.class)`, `Library.loadLibrary(I.class, "c", ...)` and their `Map`-options overloads — legacy static factory

**Output:** `jnr_ffi_hits.txt`

```
Format: interface | lib | symbol | apiPattern | jar
```

**Limitations:** Same as JNA interface mapping — runtime-computed library names are unresolvable.

---

## Running the Detectors

The pipeline (`scripts/run_analysis.sh`) runs everything through `JNADetector`:

```bash
mvn -f pom.xml -q clean compile exec:java \
  -Dexec.mainClass=com.echotrace.app.bytecode_new.JNADetector \
  -Dexec.args="<JARFILES_dir> <outputs_dir> <RUNTIME_dir>"
```

It writes each detector's hits, the merged `jna_hits.txt` / `ffi_all_hits.txt` (`Format: detector | payload`), `analyzed_jars.txt`, and `native_methods.txt` into `<outputs_dir>`.

Each detector can also be run on its own after `./build.sh`. The SootUp detectors take `<jars-dir> [outDir]`; add `-Ddetector.runtime.dir=<RUNTIME_dir>` to put the container JDK on the analysis classpath. Without `outDir`, `JnaIfaceDetector`, `JnaDynDetector` and `JnaDirectMapDetector` write to `outputs_<name>/` (derived from `JARFILES_<name>`), while `FfiDetector` and `JnrFfiDetector` write to the current directory.

```bash
CP="target/echotrace-1.0-SNAPSHOT.jar:target/deps/*"

# JNI static (Mode 1, ASM; --runtime puts the container JDK on the class loader)
java -cp "$CP" com.echotrace.app.bytecode_new.PrototypeFinal <app-jars-dir> --1 --runtime <runtime-jars-dir>

# JNI static (Mode 2, SootUp)
java -cp "$CP" com.echotrace.app.bytecode_new.PrototypeFinal <app-jars-dir> <deps-jars-dir> --2

# JNA Interface Mapping
java -cp "$CP" com.echotrace.app.bytecode_new.JnaIfaceDetector <jars-dir> [outDir]

# JNA Dynamic
java -cp "$CP" com.echotrace.app.bytecode_new.JnaDynDetector <jars-dir> [outDir]

# JNA Direct Mapping
java -cp "$CP" com.echotrace.app.bytecode_new.JnaDirectMapDetector <jars-dir> [outDir]

# Panama FFI
java -cp "$CP" com.echotrace.app.bytecode_new.FfiDetector <jars-dir> [outDir]

# jnr-ffi
java -cp "$CP" com.echotrace.app.bytecode_new.JnrFfiDetector <jars-dir> [outDir]

# JNI Dynamic (binary-level, normally run by mapped_updated.py)
python3 scripts/extract_jni_bindings.py --libs-dir <LIBS_dir> [--output-dir <dir>]
python3 scripts/extract_registernatives_binary.py <LIBS_dir>/libjvm.so <LIBS_dir>/libjava.so
```

---

## How Results Feed into the Pipeline

JNI natives and JNA/FFI bindings take separate paths to SysPart. The mapper only reads `native_methods.txt`; the JNA/FFI hits already name their library and symbol, so `analyse_jna_ffi.py` seeds SysPart with them directly.

```
 Bytecode (JNADetector)                     Binary (LIBS_<IMG_NAME>)
 ──────────────────────                     ────────────────────────
 PrototypeFinal ──→ native_methods.txt      extract_jni_bindings.py
        │                                   extract_registernatives_binary.py
        │                                              │
        ▼                                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │              mapped_updated.py (mapper)                 │
 │  Maps Java methods → C symbols → owning .so library     │
 └─────────────────────────────────────────────────────────┘
                          │
                          ▼
              mapped_method_syscalls.txt
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │           SysPart (binary value-flow analysis)          │
 │     Traces C functions → reachable Linux syscalls       │
 └─────────────────────────────────────────────────────────┘
                          │
                          ▼
              merge_all_syscalls.py ──→ seccomp profile
                          ▲
                          │
 JnaIfaceDetector ─┐      │
 JnaDynDetector ───┤      │
 JnaDirectMap... ──┼─→ jna_hits.txt ────────→ analyse_jna_ffi.py ──→ SysPart
 FfiDetector ──────┤   ffi_all_hits.txt       (jna_ffi_analysis/union_syscalls.txt)
 JnrFfiDetector ───┘
```
