# JNI dynamic binding extraction

This note describes **one** way EchoTrace recovers **JNI dynamic registrations**: bindings established with `RegisterNatives` and encoded as `JNINativeMethod[]` tables (method name, JNI type signature, native function pointer). That surface is **not** the same as scanning bytecode for `native` declarations—see [JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md) for `ACC_NATIVE` and cross-JDK coverage.

The work is implemented today as **several small extractors** in the repository; they share the same **idea** and we plan to **merge** them into a single tool later. Until then, treat the following as **one pipeline** described once.

---

## What we are recovering

At runtime, the JVM can attach native implementations to Java methods in two broad ways:

- **Static naming** — the VM looks for `Java_<mangled_pkg_class>_<method>` in loaded `.so` files.
- **Explicit registration** — native code calls `RegisterNatives(env, jclass, JNINativeMethod *methods, jint nMethods)`.

Our extractors target the second: each row is logically **`(name, signature, fn_ptr)`**. On 64-bit LP64 ELFs, that row is **24 bytes**: three little-endian pointers. We **decode** those pointers into:

1. A **Java method name** (C string in read-only or relocated data).
2. A **JNI type signature** (another C string, normally starting with `(`).
3. A **native code address** resolved to a **symbol** where possible (`nm`, or trust the source label).

From that we can relate **Java FQCN + method + signature** to **ELF / HotSpot symbols**, which downstream mapping (seccomp, syscall tagging, post-processing of `native_methods.txt`, and friends) can consume alongside bytecode-derived inventories.

---

## How we do it (unified workflow)

**1. Choose an artifact**

- **Vendor or app shared libraries** (Netty transport, Hadoop, etc.) — scan the `.so`.
- **The JVM itself** (`libjvm.so`) — same binary layout for registration tables that live in **data** or **RELRO** segments.
- **OpenJDK source** — when the table is static C/C++ initializer syntax rather than something we want to hunt only in the binary.

**2. Find a table (or many candidates)**

We need the **address or file offset** of something that looks like a contiguous array of `JNINativeMethod` rows. Depending on the build:

- **Generic ELF scan** — look for relocated pointer triples in **read-only RELRO** (`.data.rel.ro`, …) that cluster into valid(name, sig, fn) patterns, optionally scoped to libraries that export `JNI_OnLoad`.
- **Anchored scan** — use **`nm`** (or the symbol table) to locate a known static array symbol (for example Netty’s `fixed_method_table` / `statically_referenced_fixed_method_table`, or a JFR array whose VMA was determined for a given `libjvm.so` build), then convert **virtual address → file offset** with section layouts (`readelf`, or `pyelftools` where available).

**3. Validate each row**

For every 24-byte slot:

- Follow `name_ptr` and `sig_ptr` through the section map and read **null-terminated UTF-8 strings**.
- Check the name looks like a **Java identifier** and the signature looks like a **JNI descriptor** (parameters in parentheses, return type after).
- Follow `fn_ptr` into **executable text** (or a plausible PLT target) and resolve a **symbol name** when the binary is not fully stripped.

Invalid or sentinel rows end the scan (or mark the boundary between tables).

**4. Attach the Java class**

Bytecode alone does not always tell you which `RegisterNatives` call owns a row; we **infer** the declaring class by context:

- **Source path and table literals** — OpenJDK maps known HotSpot / libjava filenames to `java.lang.Thread`, `jdk.internal.misc.Unsafe`, `jdk.jfr.internal.JVM`, and similar.
- **C symbol naming** — many third-party libraries encode package stems (`netty_epoll_*`, `netty_unix_*`, …) in the native symbol; rules map those stems back to a Java FQN with a **confidence** tag where the binary also contains a corroborating string.

**5. Emit bindings**

Output is **one registration per line** (exact formatting varies slightly today; the merge will normalize this). Conceptually each line answers: **which Java method (class.name(signature)) is implemented by which native symbol, from which library or OpenJDK component**, with a note on how we **proved** the link (high-confidence string match, symbol inference, or source scan).

### Examples — same workflow, different anchors

The steps above are the same; only the **artifact** and **how you find the first row** change. Below are the tables we usually mean when we say **JFR**, **Netty**, or **HotSpot / `libjvm`**.

---

#### JFR (`libjvm.so`, binary anchor)

JFR registers dozens of natives onto **`jdk.jfr.internal.JVM`**. In a given **`libjvm.so`** build, HotSpot lays down a fixed **`JNINativeMethod[]`** (often in **`.data`**): each slot is still the usual **24-byte triple** of pointers.

| What | Detail |
|------|--------|
| **Java class** | `jdk.jfr.internal.JVM` |
| **Typical table** | One contiguous array of `JNINativeMethod` rows for JFR’s `RegisterNatives` bundle (not a separate symbol name you rely on in every distro—**the VMA / file offset is build-specific**). |
| **How we anchor** | `readelf` / section map to turn a **known VMA** or **file offset** into the array start, then walk rows until a slot fails JNI validation. You pass the **`libjvm.so` path**, the **array’s file offset** (hex, e.g. `0x12c6f40` on one Cassandra/Tomcat-era build), and an optional **row cap** (often **~57** for JFR on that family of builds); the **offset must be rediscovered** for each `libjvm.so` you care about. |
| **Example output shape** | `jdk.jfr.internal.JVM.<method><signature> → <native_symbol>` (stdout lines; stderr carries `#` comments). |

**Example table shapes in source:** HotSpot builds this table in **`jfrJniMethodRegistration.cpp`**; the **binary anchor** in `libjvm.so` is the same logical rows after link/relocation.

```c
// hotspot/share/jfr/jni/jfrJniMethodRegistration.cpp (abbreviated)
JfrJniMethodRegistration::JfrJniMethodRegistration(JNIEnv* env) {
  jclass jfr_clz = env->FindClass("jdk/jfr/internal/JVM");
  if (jfr_clz != NULL) {
    JNINativeMethod method[] = {
      (char*)"beginRecording", (char*)"()V", (void*)jfr_begin_recording,
      (char*)"isRecording", (char*)"()Z", (void*)jfr_is_recording,
      (char*)"endRecording", (char*)"()V", (void*)jfr_end_recording,
      (char*)"counterTime", (char*)"()J", (void*)jfr_elapsed_counter,
      (char*)"getPid", (char*)"()Ljava/lang/String;", (void*)jfr_get_pid,
      ...
    };
    env->RegisterNatives(jfr_clz, method,
        (jint)(sizeof(method) / sizeof(JNINativeMethod)));
  }
}
```

`nativeLookup.cpp` also lists the **`Java_jdk_jfr_internal_JVM_registerNatives`** stub (see **JVM** example below) that points at the C entry **`jfr_register_natives`**, which is how this table gets wired during VM startup.

---

#### Netty transport (`.so`, symbol anchor)

Netty’s C sources name static arrays that become symbols in **`libnetty_transport_native_epoll_*.so`**, **`libnetty_transport_native_io_uring_*.so`**, and related bundles. We **`nm -n`** those libraries and grep for the array symbol, map VMA → file offset, then decode the same **24-byte** rows.

| Array symbol (C source) | Typical Java class |
|-------------------------|-------------------|
| **`fixed_method_table`** (`transport-native-epoll/.../netty_epoll_native.c`) | `io.netty.channel.epoll.Native` |
| **`statically_referenced_fixed_method_table`** (epoll static JNI) | `io.netty.channel.epoll.NativeStaticallyReferencedJniMethods` |
| **`statically_referenced_fixed_method_table`** (`.../netty_unix_limits.c`) | `io.netty.channel.unix.LimitsStaticallyReferencedJniMethods` |
| **`statically_referenced_fixed_method_table`** (`transport-native-io_uring/.../netty_io_uring_native.c`) | `io.netty.channel.uring.NativeStaticallyReferencedJniMethods` |

**Example table shapes in source:** **Epoll** ships two static tables—the first is registered onto **`NativeStaticallyReferencedJniMethods`**, the second is copied into a **`malloc`**’d table (plus dynamic signatures) for **`Native`**.

```c
// transport-native-epoll/src/main/c/netty_epoll_native.c (Netty 4.1, abbreviated)

static const JNINativeMethod statically_referenced_fixed_method_table[] = {
 { "epollet", "()I", (void *) netty_epoll_native_epollet },
 { "epollin", "()I", (void *) netty_epoll_native_epollin },
 { "epollout", "()I", (void *) netty_epoll_native_epollout },
 ...
};

static const JNINativeMethod fixed_method_table[] = {
 { "eventFd", "()I", (void *) netty_epoll_native_eventFd },
 { "timerFd", "()I", (void *) netty_epoll_native_timerFd },
 { "epollCreate", "()I", (void *) netty_epoll_native_epollCreate },
 { "epollWait0", "(IJIIIIJ)J", (void *) netty_epoll_native_epollWait0 },
 ...
};
```

**Example discovery** (conceptual):

```text
nm -n libnetty_transport_native_epoll_x86_64.so | grep -E 'fixed_method_table|statically_referenced_fixed_method_table'
```

Then supply the chosen **VMA** (or resolved **symbol** for the array), a **max row count**, and the expected **Java FQN** for that table; overshooting the row cap is fine—the walk **stops at the first invalid triple**.

---

#### HotSpot JVM (OpenJDK **source**, table literals)

For the VM’s own natives we often **skip guessing in the binary** and read **`JNINativeMethod methods[] = { … }`** straight out of the OpenJDK tree. Each brace entry is still **name + JNI signature + native target** (`JVM_*`, `Unsafe_*`, etc.).

**Example table shapes in source — libjava (`java.lang.Thread`):**

```c
// java.base/share/native/libjava/Thread.c (JDK 17; member list varies by release)
#define THD "Ljava/lang/Thread;"
#define OBJ "Ljava/lang/Object;"

static JNINativeMethod methods[] = {
    {"start0",        "()V",        (void *)&JVM_StartThread},
    {"stop0",         "(" OBJ ")V", (void *)&JVM_StopThread},
    {"suspend0",      "()V",        (void *)&JVM_SuspendThread},
    {"setPriority0",  "(I)V",       (void *)&JVM_SetThreadPriority},
    {"yield",         "()V",        (void *)&JVM_Yield},
    {"sleep",         "(J)V",       (void *)&JVM_Sleep},
    {"currentThread", "()" THD,     (void *)&JVM_CurrentThread},
    ...
};

JNIEXPORT void JNICALL
Java_java_lang_Thread_registerNatives(JNIEnv *env, jclass cls)
{
    (*env)->RegisterNatives(env, cls, methods, ARRAY_LENGTH(methods));
}
```

**Example table shapes in source — `nativeLookup` (JNI-mangled `registerNatives` stubs):**

```c
// hotspot/share/prims/nativeLookup.cpp (abbreviated; signatures are NULL in the table)

static JNINativeMethod lookup_special_native_methods[] = {
  { CC"Java_jdk_internal_misc_Unsafe_registerNatives",
      NULL, FN_PTR(JVM_RegisterJDKInternalMiscUnsafeMethods) },
  { CC"Java_java_lang_invoke_MethodHandleNatives_registerNatives",
      NULL, FN_PTR(JVM_RegisterMethodHandleMethods) },
#if INCLUDE_JFR
  { CC"Java_jdk_jfr_internal_JVM_registerNatives",
      NULL, FN_PTR(jfr_register_natives) },
#endif
  ...
};
```

Rows here use **`Java_<mangled>_registerNatives`** as the *name* field; we **demangle** those strings back to classes like **`jdk.internal.misc.Unsafe`**, **`jdk.jfr.internal.JVM`**, **`java.lang.invoke.MethodHandleNatives`**, … so you still get **class + `registerNatives` + handler symbol** lines consistent with merging next to libjava-style tables.

**Emit shape (typical):** `libjvm.so|<JavaFQN>|<jniSig>|<C_symbol>|SRC_SCAN` — same **logical** fields as ELF mining, but **provenance** is **source parse**, not RELRO.

---

## What this is not

- **Not a substitute for running the JVM** — we do not execute `JNI_OnLoad` or follow dynamic `malloc`’d tables built at runtime.
- **Not guaranteed on odd ABIs** — we assume LP64 triples and sensible RELRO / section metadata; fully relocated or pathological binaries may not yield tables.
- **Not identical to HotSpot’s `JVM_*` catalog** — that catalog is partly maintained in C++ source; source extraction aligns with it, while generic `.so` mining discovers **vendor** registrations the VM never lists.

---

## Related files

| Topic | Location |
|------|----------|
| Bytecode `native` scan + cross-JDK tests | [JNI_INTERFACE_DETECTION.md](./JNI_INTERFACE_DETECTION.md) |
| ELF / RELRO table mining (generic `.so`) | Design notes kept alongside the repository extractors |

---

## Summary

**JNI dynamic binding** extraction means: **locate `JNINativeMethod[]`-shaped data**, **decode pointers into Java names and JNI signatures**, **resolve function pointers to symbols**, and **label the owning Java class**—whether the evidence comes from **RELRO in a `.so`**, **a known array anchor in `libjvm.so`**, **Netty’s transport tables**, or **OpenJDK C++ sources**. Today’s extractors are **split for historical reasons**; together they implement **one** recovery strategy with different **inputs and anchors**.
