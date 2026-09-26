# Native Method Detection

This directory contains EchoTrace's bytecode analysis detectors. Each detector targets a different mechanism by which Java code invokes native (C/C++) functions.

For a **deep dive on JNI static detection**, **`PrototypeFinal`**, **application vs JDK natives**, and **cross-JDK JUnit results**, see **[JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md)**.

## Overview

Java applications reach native code through several interfaces. Each has a distinct bytecode signature that requires a specialized detection strategy:

| Type | Detector | What it finds |
|------|----------|---------------|
| JNI Static | `PrototypeFinal` / `Mode4NativeScanner` | `native` keyword declarations |
| JNI Dynamic | `JNIDyn` | Libraries using `RegisterNatives()` |
| JNA Interface Mapping | `JnaIfaceDetector` | Interfaces extending `com.sun.jna.Library` |
| JNA Dynamic | `JnaDynDetector` | `NativeLibrary.getInstance().getFunction()` |
| JNA Direct Mapping | `JnaDirectMapDetector` | Classes calling `Native.register()` |
| Panama FFI | `FfiDetector` | `java.lang.foreign` / `jdk.incubator.foreign` |
| jnr-ffi | `JnrFfiDetector` | `LibraryLoader.create().load()` |

---

## 1. JNI Static Binding

**File:** `PrototypeFinal.java`, `Mode4NativeScanner.java`

**Java pattern:**
```java
public class System {
    public static native long nanoTime();
}
```

**How we detect it:**
- Scan all `.class` files in target/dependency JARs using ASM
- Any method with the `ACC_NATIVE` modifier flag is a native method
- SootUp `MethodModifier.NATIVE` confirms in Jimple IR

**Symbol naming convention:**
The JVM resolves these automatically to `Java_<package>_<Class>_<method>`:
```
java.lang.System.nanoTime  →  Java_java_lang_System_nanoTime (in libjava.so)
```

**Output:** `native_methods.txt` (one fully-qualified method per line)

**Limitations:** None for detection. The method is always visible in bytecode. The harder problem is *mapping* the method to a library (done downstream by `mapped_updated.py`).

---

## 2. JNI Dynamic Binding (RegisterNatives)

**File:** `JNIDyn.java`

**C pattern (inside `.so`):**
```c
static JNINativeMethod methods[] = {
    {"beginRecording", "()V", (void*)jfr_begin_recording},
    {"isRecording",    "()Z", (void*)jfr_is_recording},
};

JNIEXPORT void JNI_OnLoad(JavaVM *vm, void *reserved) {
    (*env)->RegisterNatives(env, cls, methods, 3);
}
```

**How we detect it:**
1. Parse ELF `.so` files directly (no bytecode needed for detection)
2. Check for `JNI_OnLoad` in the dynamic symbol table (`nm -D`)
3. Scan raw bytes for the string `"RegisterNatives"` (indicates the library calls it)
4. Cross-reference with native methods from Step 1 to identify which methods are dynamically bound

**Signal levels:**
- `HIGH` — Both `RegisterNatives` string AND `JNI_OnLoad` exported symbol present
- `MEDIUM` — `RegisterNatives` string present, `JNI_OnLoad` not exported
- `LOW` — `JNI_OnLoad` present but no `RegisterNatives` string

**Output:** `jni_dynamic_report.txt`

**Resolution:**
The actual Java→C mapping is extracted by `jfr_registernative_mapping.sh` which disassembles the `.so` to recover the `JNINativeMethod[]` array contents (method name, signature, function pointer).

**Limitations:** Only works on non-stripped binaries with intact symbol tables. Pointer-based entries where the method name/sig aren't string literals cannot be resolved statically.

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
1. **PASS 1 (class discovery):** Find all interfaces whose hierarchy includes `com.sun.jna.Library` (BFS traversal through `StdCallLibrary`, `ALTLibrary`, custom intermediates)
2. **PASS 1 (load site analysis):** Scan `<clinit>` and field initializers for `Native.load("libname", Interface.class)` — extract the library name from the first `StringConstant` argument
3. **PASS 2 (method enumeration):** For each detected Library interface, every declared method name IS the native symbol name (JNA convention: method name = C function name)

**Taint tracking:**
- Tracks `Native.load()` return value through field assignments (`INSTANCE = Native.load(...)`)
- Handles `Native.synchronizedLibrary(...)` wrappers
- Handles conditional library names (`Platform.isWindows() ? "msvcrt" : "c"`)

**Output:** `jna_iface_hits.txt`
```
lib=c | symbol=strlen | iface=com.example.CLib | jar=app.jar | api=Native.load(String,Class)
```

**Limitations:** If the library name is computed at runtime (not a string constant), we output `lib=<?>`.

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
1. **PASS 1 (taint propagation):** Track `NativeLibrary.getInstance("libname")` return values through locals and fields → builds `local/field → library name` map
2. **PASS 1 (function resolution):** Track `.getFunction("symbolName")` calls → builds `local/field → FuncInfo(lib, symbol)` map
3. **PASS 2 (invoke detection):** Detect `Function.invoke*()` calls and resolve the receiver back to a `FuncInfo` via taint

**API variants detected:**
- `NativeLibrary.getInstance(String)` → lib from string constant
- `NativeLibrary.getFunction(String)` → symbol from string constant
- `Function.getFunction(String, String)` → lib + symbol directly
- `Function.getFunction(Pointer)` → **unresolvable** (COM vtable)

**Output:** `jna_dyn_hits.txt`
```
lib=c | symbol=mmap | caller=com.example.NativeUtils.doMmap | api=NativeLibrary.getFunction
```

**Limitations:**
- `Function.getFunction(Pointer)` with a runtime pointer (COM vtable dispatch) — outputs `lib=<?>, symbol=<?>` because the vtable offset doesn't reveal the function name
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
1. **PASS 1:** Scan `<clinit>` of every class for calls to `Native.register(String)` or `Native.register(Class, String)` or `Native.register(NativeLibrary)` — extract library name
2. **PASS 2:** For each class that called `register()`, enumerate all methods with `ACC_NATIVE` modifier — each method name IS the C symbol (JNA direct-mapping convention)

**Key difference from Interface Mapping:** Direct mapping uses `native` method declarations (like JNI) but resolves them at class-load time via JNA's runtime registration, not the JVM's standard `Java_*` symbol lookup.

**Output:** `jna_directmap_hits.txt`
```
lib=c | symbol=strlen | class=com.example.CLibrary | api=Native.register(String)
```

**Limitations:** If `Native.register(NativeLibrary.getInstance(computedName))` uses a runtime-computed name, we output `lib=<?>`.

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
1. **PASS 1 (library discovery):** Track `SymbolLookup.libraryLookup("libname", ...)` or `LibraryLookup.ofLibrary("libname")` — extract library name via StringConstant
2. **PASS 1 (symbol resolution):** Track `.find("symbol")` / `.lookup("symbol")` calls — extract symbol name
3. **PASS 1 (handle binding):** Track `Linker.downcallHandle(addr, ...)` — connect handle to the resolved symbol
4. **PASS 2 (invoke detection):** Detect `MethodHandle.invokeExact(...)` / `invoke(...)` and resolve receiver back to library+symbol

**Both API generations detected:**
- `java.lang.foreign.*` (Java 22+ finalized)
- `jdk.incubator.foreign.*` (Java 17-21 incubator)

**Output:** `ffi_hits.txt`
```
lib=ssl | symbol=SSL_read | caller=com.example.SslWrapper.read | api=SymbolLookup.libraryLookup
```

**Limitations:**
- `Linker.nativeLinker().defaultLookup().find(...)` resolves symbols from the default (libc) lookup — library is tagged as `<default>`
- If the symbol name is computed at runtime, outputs `symbol=<?>`

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
1. **PASS 1:** Scan `<clinit>` for `LibraryLoader.create(Interface.class).library("libname").load()` chains or `Library.loadLibrary(Interface.class, "libname")` calls — extract interface + library name
2. **PASS 2:** For each discovered interface, enumerate all declared methods — each method name IS the C symbol (same convention as JNA)

**API variants:**
- `LibraryLoader.create(I.class).library("c").load()` — chained builder
- `LibraryLoader.create(I.class).load("c")` — direct string
- `Library.loadLibrary(I.class, "c")` — legacy static factory

**Output:** `jnr_ffi_hits.txt`
```
lib=c | symbol=getpid | iface=org.jruby.ext.ffi.LibC | api=LibraryLoader.create().library().load()
```

**Limitations:** Same as JNA interface mapping — runtime-computed library names are unresolvable.

---

## Running the Detectors

All detectors use SootUp for bytecode analysis (Jimple IR) and are run against the target application's JAR directory:

```bash
# JNI static (Mode 1: scan <app-jars-dir>; add --runtime <dir> for staged java.base / modular JARs)
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.PrototypeFinal <app-jars-dir> --1 [--runtime <runtime-jars-dir>]

# JNA Interface Mapping
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.JnaIfaceDetector <jars-dir>

# JNA Dynamic
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.JnaDynDetector <jars-dir>

# JNA Direct Mapping
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.JnaDirectMapDetector <jars-dir>

# Panama FFI
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.FfiDetector <jars-dir>

# jnr-ffi
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.JnrFfiDetector <jars-dir>

# JNI Dynamic (binary-level, not bytecode)
java -cp "target/echotrace-1.0-SNAPSHOT.jar:target/deps/*" \
  com.echotrace.app.bytecode_new.JNIDyn <libs-dir> <native_methods.txt>
```

---

## How Results Feed into the Pipeline

```
 Bytecode Detectors                    Binary Analysis
 ──────────────────                    ───────────────
 PrototypeFinal ──→ native_methods.txt
 JnaIfaceDetector ──→ jna_iface_hits.txt
 JnaDynDetector ──→ jna_dyn_hits.txt        jfr_registernative_mapping.sh
 JnaDirectMapDetector ──→ jna_directmap_hits.txt       │
 FfiDetector ──→ ffi_hits.txt                          │
 JnrFfiDetector ──→ jnr_ffi_hits.txt                  │
 JNIDyn ──→ jni_dynamic_report.txt                     │
        │                                              │
        ▼                                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │              mapped_updated.py (mapper)                  │
 │  Maps Java methods → C symbols → owning .so library     │
 └─────────────────────────────────────────────────────────┘
                          │
                          ▼
              mapped_method_syscalls.txt
                          │
                          ▼
 ┌─────────────────────────────────────────────────────────┐
 │           SysPart (binary value-flow analysis)           │
 │     Traces C functions → reachable Linux syscalls        │
 └─────────────────────────────────────────────────────────┘
                          │
                          ▼
                  seccomp profile
```
