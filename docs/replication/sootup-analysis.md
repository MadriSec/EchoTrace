# SootUp bytecode analysis: version and supported rules

This note records the SootUp configuration and the custom propagation rules
used by EchoTrace's Java binding detectors. SootUp supplies the Java bytecode
front end and Jimple bodies; EchoTrace implements the binding-specific value
tracking described below.

## Version

The replication build pins its SootUp dependencies in `pom.xml` to **2.0.0**.
This includes `sootup.core`, the Java core and bytecode/source front ends,
callgraph, intraprocedural/interprocedural analysis, Qilin, and
code-property-graph artifacts. The previously declared `sootup.jimple.parser`
1.3.0 dependency was unused by the source tree and has been removed; it did not
have a resolvable 2.0.0 artifact in the configured repository. Keep the
remaining SootUp versions aligned when changing the dependency set.

## Common propagation

The detectors inspect Jimple bodies and use custom, detector-local maps. Their
common tracked facts include constant strings and native-binding objects or
values (library handles, symbols, and function/method handles). Supported
intra-method flow includes:

- A constant string assigned to a local, followed by local-to-local copies.
- A tracked local assigned to a field and later read from that field, keyed by
  the field signature. Detectors track only the fact types their rule needs.
- Cast-unwrapped assignments and returns where that detector explicitly calls
  the cast-unwrapping helper.
- Values passed as recognized API arguments or receivers, when a detector has
  a rule for that API. This is not general propagation through every call.

The detectors do not run one general interprocedural taint analysis. Helper
calls are handled by the specific summaries below, keyed by method signature.
Most summaries require a body and a recognizable return/assignment pattern.

## Supported binding and helper-call rules

| Detector | Binding rules and helper summaries |
| --- | --- |
| JNA interface (`JnaIfaceDetector`) | Recognizes `Native.load` and `Native.loadLibrary` string/class overloads, class-only overloads (current process/default C library), and `null` library arguments. Tracks constant and conditional library-name strings through locals and fields. Propagates a loaded library through `Native.synchronizedLibrary`. Summarizes helpers that return a value from those load/wrapper calls; follows synthetic `access$...` methods that return a tracked field. The taint/summary pass is capped at 4 iterations. |
| JNA dynamic (`JnaDynDetector`) | Recognizes `NativeLibrary.getInstance` / `getFunction` and supported `Function.getFunction` forms, then associates library and symbol with `Function.invoke*` sinks. Tracks values through locals and fields. Summarizes constant-string helpers, helpers returning `NativeLibrary`, and helpers returning `Function`; a Function summary may obtain its symbol from a call-site string parameter or its library from a tracked field. The population pass is capped at 4 iterations. |
| JNA direct registration (`JnaDirectMapDetector`) | Recognizes the supported `Native.register` overloads. Propagates constant library strings through locals and summarized string-returning helpers. Helper summaries are iterated to a fixed point, capped at 5 iterations. |
| JNR-FFI (`JnrFfiDetector`) | Scans class initializers for recognized `LibraryLoader` creation, `.library(...)`, and `.load(...)` chains (including the supported `Library.loadLibrary` form), associates the loaded interface with library name(s), then maps declared interface methods to same-named native symbols. The initializer scan runs twice to pick up order-dependent discoveries. This is a constrained initializer/API-pattern analysis, not general helper summarization. |
| FFM / Panama (`FfiDetector`) | Tracks strings, `SymbolLookup` library facts, symbol names, and downcall handles through local and field assignments. Recognizes supported `SymbolLookup`/`LibraryLookup` and `Linker`/`CLinker` lookup and `downcallHandle` patterns, including the incubator API names. Handles `System.getProperty(key, default)` by propagating a known default, and a `findOrThrow(String)` helper by taking its string argument and the library associated with its declaring class. Descriptor-only downcalls use the detector's callback/name heuristics. The taint pass is capped at 4 iterations. |

## Scope and limitations

These are bounded pattern-based rules. They do not establish that a binding is
executed, nor do they model arbitrary reflection, dynamically generated
classes, all virtual-dispatch targets, arbitrary string computation, or
unrecognized wrapper methods. A helper is resolved only where a detector has
an explicit summary rule; recursive or long helper chains can exceed the
iteration cap. Treat emitted `(library, symbol)` pairs as recovered candidates
and retain skipped/unresolved-method reports when reproducing results.

The separate `PrototypeFinal` native-declaration scan is not a SootUp
propagation rule: the main pipeline invokes it in ASM mode.
