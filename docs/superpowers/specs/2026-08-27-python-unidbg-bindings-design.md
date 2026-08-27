# Python unidbg bindings design

## Purpose

`pyunidbg` makes unidbg usable from Python without requiring each user or agent to create, build, and repeatedly edit a Gradle project. A user installs the package, imports `pyunidbg`, constructs an Android ARM64 emulator, and works interactively with native libraries, JNI, memory, and hooks.

The primary acceptance target is a behavior-preserving Python rewrite of `/home/ujhhgtg/coding/wechatx_deobf/unidbg-harness/src/main/java/x/DecryptorHarness.java`.

## Supported environment

Version 0.1 intentionally targets one current development environment:

- Linux x86_64 only
- CPython 3.14
- a Java 17 or newer executable available as `java` on `PATH`
- Android ARM64 emulation only
- unidbg 0.9.9
- the default Unicorn backend bundled with unidbg

macOS, Windows, Linux architectures other than x86_64, Android ARM32, iOS, alternate backends, older Python versions, and bundled Java runtimes are out of scope. Unsupported platforms fail before starting the JVM.

## Architecture

Python embeds one JVM in the current process through JPype. A lazy process-wide runtime builds its classpath from artifacts shipped inside the Python package, validates the host and Java version, configures the bundled Linux native-library path, and starts the JVM on first emulator creation. Importing `pyunidbg` alone does not start Java.

The public API consists of small Python wrappers around unidbg objects. Wrappers translate only unambiguous values and expose the underlying JPype object through `.java`. This escape hatch is part of the supported API so unusual unidbg operations do not require an immediate new Python wrapper.

Python cannot directly subclass unidbg's `AbstractJni`. A small Java helper therefore extends `AbstractJni` and delegates supported callback groups to a Java interface implemented by Python through JPype. The helper invokes the superclass behavior when Python returns the `NOT_HANDLED` sentinel. It does not otherwise mirror or facade the unidbg API.

The runtime is in-process rather than an RPC subprocess. This preserves direct callbacks, interactive debugging, Java exception details, and low call overhead. Process isolation, remote execution, handle tables, and callback serialization are out of scope.

## Components

### Runtime

`pyunidbg.runtime` is responsible for:

- checking Linux x86_64 and CPython 3.14
- locating `java` on `PATH` and verifying Java 17 or newer
- locating packaged JARs and native libraries through package resources
- starting JPype once with the complete classpath and native-library configuration
- loading Java classes by name for wrappers and the public `java_class()` escape hatch
- detecting a JVM that another component started without the pyunidbg classpath and raising a clear error

The runtime never automatically shuts down the JVM. JPype cannot safely restart a JVM in the same process, while individual emulator instances can be created and closed normally.

### Emulator and modules

`AndroidEmulator` creates unidbg's ARM64 Android builder and owns its emulator, Android resolver, Dalvik VM, and cleanup lifecycle. Its initial constructor is:

```python
AndroidEmulator(
    process_name: str,
    *,
    api_level: int = 23,
    root_dir: str | Path | None = None,
    apk: str | Path | None = None,
    verbose: bool = False,
)
```

It supports explicit `close()` and the context-manager protocol. `close()` is idempotent. Emulator instances are single-thread-owned.

`load_library(path, *, call_jni_on_load=False)` returns a `Module`. A module exposes its load base, JNI-on-load invocation, native calls by symbol and module-relative offset, and breakpoints by module-relative offset. Absolute-address operations remain available through `.java`.

### Memory, pointers, and register context

`Memory` exposes allocation plus byte and typed integer/pointer reads and writes. Allocations retain their unidbg `MemoryBlock` owner so the backing allocation remains alive. `Pointer` provides address arithmetic and equivalent reads and writes.

Breakpoint callbacks receive the wrapped emulator, hit address, and `RegisterContext`. The context exposes ARM64 integer and pointer arguments, LR, PC, and direct register access. A callback can update registers, including PC, and read or write emulated memory. Returning `True` uses unidbg's normal breakpoint continuation contract.

### Dalvik VM values and JNI calls

`VM` exposes:

- `resolve_class(name, *parents)` for class creation and explicit hierarchy registration
- `set_jni(handler)`
- factories `string()`, `bytes()`, `boolean()`, `integer()`, and `array()`
- `.java` for direct VM operations

`DvmClass` exposes `new_object(value=None)` and `call_static_jni(signature, *args)`. `DvmObject` exposes `call_jni(signature, *args)` and its wrapped value where unidbg provides one. Both retain `.java`.

The convenience factories accept Python primitives and create unidbg's standard `StringObject`, `ByteArray`, `DvmBoolean`, `DvmInteger`, and `ArrayObject` values. Advanced or ambiguous values must be constructed with Java objects through `java_class()` or direct `.java` access. Version 0.1 will not introduce a Python-object identity registry.

### JNI handler

Users subclass `JniHandler`. It exposes the callback groups required by the acceptance harness:

- object method
- static object method
- object construction
- void method
- boolean method
- integer method
- long method
- static long method

Each callback receives wrapped VM/object/class values, the exact JNI signature, and a `VaList` wrapper with typed argument access. Returning `NOT_HANDLED` delegates to `AbstractJni`. Valid falsey values such as `None`, `False`, and `0` are real handled results rather than fallthrough signals.

The helper converts wrapper results back to the Java return type expected by unidbg. If a Python callback raises, the helper propagates that failure immediately with the Python cause preserved. It never silently delegates after an exception.

Java standard-library cryptography, certificates, ZIP streams, file streams, and buffers used by the WeChatX rewrite are accessed through `java_class()`. This retains the original harness semantics without building parallel Python state adapters.

## Example API

```python
import pyunidbg

with pyunidbg.AndroidEmulator(
    process_name="com.example.app",
    api_level=23,
    root_dir="rootfs",
) as emulator:
    module = emulator.load_library("libnative.so")

    block = emulator.memory.malloc(0x40)
    block.pointer.write_u32(0x20, 0xFFFFFFFF)

    @module.breakpoint(0x1234)
    def inspect_call(emulator, address, context):
        first_argument = context.pointer_arg(0)
        print(first_argument.read(16).hex())
        return True

    module.call_jni_on_load()
    loader = emulator.vm.resolve_class("com/example/Loader")
    result = loader.call_static_jni(
        "decrypt([B)[B",
        emulator.vm.bytes(b"input"),
    )
```

Both decorator-style and direct `add_breakpoint(offset, callback)` registration refer to the same operation; the decorator is only syntax sugar and not a separate hook framework.

## Packaging and artifact provenance

The installed package performs no network access and invokes no build system. Its wheel contains:

- unidbg 0.9.9 Android/API/backend JARs required by the selected runtime
- all required transitive JARs
- Linux x86_64 native libraries required by the default Unicorn backend and its dependencies
- the compiled JNI callback helper
- upstream license and notice material

A maintainer-only script resolves and assembles these artifacts from pinned upstream versions. It produces a committed manifest containing every artifact's coordinate or source, version, destination, and SHA-256 hash. Package data configuration includes the artifacts in both wheels and source distributions. Runtime code consumes only the packaged files; it does not contain a fallback downloader.

JPype is the sole installed binary Python dependency and is constrained to a tested 1.7 release range that provides a CPython 3.14 Linux x86_64 wheel.

## Errors and diagnostics

Platform, Java discovery, Java-version, JVM-state, and packaged-artifact failures use concise pyunidbg exception types with actionable messages.

Once emulation begins, Java and unidbg exception types, messages, causes, and stack information remain accessible. Wrappers add operation context only when it does not discard the original exception. They do not flatten failures into a generic `UnidbgError`.

unidbg and SLF4J output initially use their normal process streams. Python callback output uses normal Python streams. Version 0.1 does not redirect or merge logging systems.

## WeChatX acceptance harness

The project includes a Python rewrite of `DecryptorHarness.java`. The rewrite keeps the original operational behavior:

- prepares an isolated root filesystem
- processes the same ten core identifiers
- loads `libwxcoreloader.so` as ARM64
- registers the same class hierarchy required for JNI dispatch
- installs equivalent breakpoint callbacks and register/memory patches
- implements the same JNI mocks and Java standard-library operations
- invokes the same `WxCoreLoader.CallMethod` JNI signatures
- captures the same decrypted DEX or payload files
- continues processing other cores after a per-core failure and reports the same success count

The rewrite uses configurable source, root, and output paths so tests do not mutate `/home/ujhhgtg/coding/wechatx_deobf`. Its defaults may target that repository because this project is intentionally built for the current machine.

The final integration test copies or reads proprietary inputs from `/home/ujhhgtg/coding/wechatx_deobf`, writes all generated state to a temporary directory, invokes the existing post-processing behavior, and verifies the final output set against the current known-good filenames, byte sizes, and SHA-256 hashes:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `C.dex` | 871900 | `c19f73b7b71e388efb435804dbd92e9bcd5b9ecd478cdd7af09c31f38cabc087` |
| `H_p.json` | 60720 | `caf77e71431ecb52abf2da26f9b2a22905987f0900433e3ceaa496fd6765c224` |
| `M.json` | 43578 | `dae818b3119c6b6af17afb631c19796336b405f685666d4106e3eb010cd716bc` |
| `P.json` | 4586 | `c285ac5ffd376b3209f48c55c6c280ed0f6e81b1c527c16961f36b36e5494edb` |
| `S.json` | 314889 | `3324fe4c4ccb6f51f538bf408ad80b263fe339149936c8ba8d372999711311ea` |
| `big.dex` | 3172208 | `d277feaa8aa6acf305f93277d6bfdc96105fca3b0440f817051c2abaa99637b2` |
| `load2.apk` | 371859 | `5a4b160635e731870c38bae36f2161b555f7d3282224e8e8bcd6a1278266e89a` |
| `load2_classes.dex` | 862668 | `ae795455cb8f3c9044fd34a37142225c7e70fb826b5ea7a3187857d9f04b478e` |
| `m1.dex` | 551084 | `76b7eb2b051c47c51f121f2e88998dabb6fe0f923e74ac974a02d21241fd8dd3` |
| `m2.dex` | 335236 | `b0a8e7807a669d21b32b610c696c0ac1573aef18105c32ed8d0e5797ae23cb67` |
| `m3.dex` | 211156 | `b589b3c2b94f53911cbee7a6f56f5318110870c2e38444ce0d03b0504e69ca13` |

The proprietary WeChatX inputs and expected output files are not copied into pyunidbg or redistributed.

## Verification strategy

Fast tests cover Python-to-Java value conversion, wrapper identity, idempotent cleanup, runtime validation, JNI dispatch, `NOT_HANDLED`, and callback exception propagation.

A small distributable ARM64 fixture provides real smoke coverage for JVM startup, native backend loading, emulated memory, ELF loading, symbol and offset calls, JNI-on-load, and breakpoint callbacks.

The WeChatX integration test is opt-in because it depends on a separate local repository and proprietary data. It is nevertheless a release acceptance requirement on the target machine: version 0.1 is not considered complete until the Python rewrite produces the recorded output set and hashes.

## Explicit non-goals

Version 0.1 does not include:

- iOS or ARM32 emulation
- macOS or Windows support
- a bundled JVM
- runtime Maven or Gradle use
- first-run downloads
- subprocess/RPC mode
- emulator pools or thread-safe sharing
- a complete handwritten mirror of every unidbg class
- Python replacements for the Java standard library
- a Python-object registry for arbitrary DVM values
- custom logging infrastructure
- compatibility guarantees beyond the pinned environment and artifacts
