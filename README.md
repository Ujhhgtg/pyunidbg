# pyunidbg

Use unidbg from Python without creating a Gradle project.

Version 0.1 deliberately supports this machine's environment: CPython 3.14 on
Linux x86_64, a Java 17+ runtime available as `java` on `PATH`, and Android
ARM64 libraries. The unidbg 0.9.9 JARs and Linux native backend are included in
the package, so emulator startup does not run Gradle, Maven, or a downloader.

## Status and API coverage

The coverage estimate is based on 17 Android ARM64 feature families, not on a
raw count of Java methods. All seventeen are covered: **100% fully wrapped**.
There are no partially covered families.

| Android ARM64 feature family | Status | Python coverage |
| --- | --- | --- |
| Emulator creation and lifecycle | Full | Process name, API level, rootfs, APK-backed VM, context manager, cleanup |
| Native library lifecycle | Full | ELF loading and `JNI_OnLoad` |
| Native invocation | Full | Calls by exported symbol or module-relative offset |
| Memory and pointers | Full | Allocation, byte access, typed integer/pointer access, address arithmetic |
| ARM64 register context | Full | Arguments, LR, register reads/writes, and PC changes |
| Breakpoints | Full | Absolute and module-relative Python callbacks |
| Dalvik VM, classes, and values | Full | Class hierarchy resolution plus string, byte, boolean, integer, object, and array values |
| JNI invocation | Full | Static and instance calls with void, boolean, integer, long, and object results |
| JNI mocking | Full | Named common callbacks plus generic typed dispatch for every method, field, allocation, reflection, and acceptance callback family |
| Debugging and tracing | Full | Read/write/code/system-memory tracing, trace redirection, debugger types, filters, breakpoints, function calls, and debugger run |
| Module and symbol inspection | Full | Metadata, regions, exports, closest/dependency symbols, needed libraries, registration, init listeners, entry calls, and unload |
| Filesystem and Android environment | Full | Rootfs operations, syscall handler controls, byte/file IO resolvers, file listeners, and APK asset resolvers |
| Advanced hooks and listeners | Full | Detachable backend hooks, module/import/mmap listeners, Dobby, HookZz, Whale, xHook, ARM64 SVCs, system properties, and leak tracking |
| MCP integration | Full | Python-native modern `/mcp` server, 42 built-in tools, custom typed tools, events, allocations, and breakpoint execution control |
| Guest thread dispatcher | Full | Task inspection, scheduler control, signal sets, waiters, destruction callbacks, and raw task injection |
| Worker pools | Full | Python-native lazy reusable pools, exclusive leases, invalidation, idle cleanup, statistics, and async execution |
| State inspection and export | Full | Bounded JSON-compatible reports for registers, modules, mappings, tasks, breakpoints, and selected memory |

Every wrapper exposes `.java`, and `pyunidbg.java_class()` provides access to
the bundled unidbg classpath, so missing convenience methods usually do not
block use from Python. Extension points that require subclassing a Java class
may still require a small Java helper, as the JNI bridge does.

This table deliberately excludes non-Android-ARM64 functionality from its
denominator. ARM32, iOS, macOS, Windows, non-x86_64 Linux hosts, and backends
other than the bundled default Unicorn backend are scope exclusions—not
uncovered API.

For JNI operations without a dedicated named callback, override
`JniHandler.handle_jni(operation, vm, target, signature, args, value)`. It
receives every remaining unidbg method/field callback with a stable snake-case
operation name and the appropriate typed return conversion.

```bash
uv add git+https://github.com/Ujhhgtg/pyunidbg
```

```python
import pyunidbg

with pyunidbg.AndroidEmulator(
    "com.example.app",
    api_level=23,
    root_dir="rootfs",
) as emulator:
    module = emulator.load_library("libnative.so")
    print(module.call_symbol("native_add", 20, 22))
```

## JNI

Create DVM values with the VM factories and call JNI methods using their normal
signatures:

```python
with pyunidbg.AndroidEmulator("com.example.app") as emulator:
    module = emulator.load_library("libnative.so", call_jni_on_load=True)
    native = emulator.vm.resolve_class("com/example/Native")
    result = native.call_static_jni(
        "decrypt([B)[B",
        emulator.vm.bytes(b"ciphertext"),
    )
    plaintext = bytes((int(byte) & 0xff) for byte in result.value)
```

Subclass `pyunidbg.JniHandler` to mock Android or Java methods. Return
`pyunidbg.NOT_HANDLED` to use unidbg's standard `AbstractJni` behavior. The
common object/static-object, constructor, void, boolean, int, long, and
static-long groups have named methods. `handle_jni()` covers every remaining
method, field, allocation, reflection, and acceptance callback.

Every wrapper has a `.java` property for direct access to APIs that do not yet
have Python convenience methods. `pyunidbg.java_class(name)` exposes any class
on the bundled JVM classpath.

## Memory and breakpoints

```python
block = emulator.memory.malloc(0x40)
block.pointer.write_u32(0x20, -1, signed=True)

@module.breakpoint(0x1234)
def inspect_call(emulator, address, context):
    first_argument = context.pointer_arg(0)
    print(first_argument.read(16).hex())
    return True
```

## Advanced hooks and listeners

Backend hooks are detachable and may be used as context managers. Address
ranges are inclusive.

unidbg 0.9.9's native Capstone instruction tracer is unsafe after a previous
emulator has been closed in the same process. Start instruction tracing in a
fresh process (or on the first emulator) when using `trace_code()`; pyunidbg's
tests enforce this boundary.

```python
with emulator.hooks.code(
    lambda emulator, address, size, data: print(hex(address)),
    begin=module.base,
    end=module.base + module.size,
) as hook:
    module.call_symbol("target")

emulator.hooks.invalid_memory(
    pyunidbg.MemoryHookMask.READ_UNMAPPED,
    lambda emulator, address, size, value, event, data: False,
)
```

Inline engines use explicit decisions instead of exposing unidbg's ambiguous
`HookStatus.RET` and `HookStatus.LR` names:

```python
emulator.inline.dobby.replace(
    module.find_symbol("target"),
    lambda emulator, context, origin: pyunidbg.HookDecision.return_value(123),
)

emulator.inline.hookzz.wrap(symbol, before=before_call, after=after_call)
emulator.inline.hookzz.instrument(address, inspect_registers)
emulator.inline.xhook.register("libtarget.so", "strlen", replace_strlen)
emulator.inline.xhook.refresh()
```

Module-load and import-symbol listeners remain active for the emulator's
lifetime because unidbg 0.9.9 has no listener-removal API. Mmap listeners are
composable and removable.

```python
emulator.listeners.module_loaded(on_module)
emulator.listeners.import_symbol(on_import)

with emulator.memory.listen_mmap(
    on_map=on_map,
    on_protect=on_protect,
    on_unmap=on_unmap,
):
    module.call_symbol("allocate")

service = emulator.register_svc(lambda emulator: 42, name="answer")
assert service.call() == 42
```

## Python-native MCP server

The MCP implementation is entirely Python-native and does not use unidbg's
Java `McpServer`, `McpTools`, or console input injection. It uses the official
Python MCP SDK and exposes modern Streamable HTTP at `/mcp`.

```python
with emulator.mcp(port=9239) as server:
    print(server.url)  # http://127.0.0.1:9239/mcp
    print(server.client_config())
```

The server binds to `127.0.0.1` by default. Non-loopback binding is rejected
unless `allow_remote=True` is explicit.

Custom tools use ordinary annotated Python functions:

```python
server = emulator.mcp()

@server.tool()
def encrypt(input: str) -> str:
    """Run the target encryption routine."""
    return run_encrypt(input)
```

Built-in tools cover modules and symbols, memory and tracked allocations,
registers, assembly/disassembly, native calls, breakpoints, stepping, tracing,
and event polling. Emulator operations are serialized through one MCP worker;
Python-managed breakpoints pause the emulation thread while MCP tools inspect
or modify state.

## Guest threads

Guest threads remain owned by unidbg's ARM scheduler; pyunidbg wraps that
scheduler instead of attempting to reproduce CPU context switching in Python.

```python
emulator.threads.enabled = True

for task in emulator.threads.tasks:
    print(task.snapshot())

emulator.threads.run_for(10, unit="milliseconds")
emulator.threads.emulate_signal(2)
```

Signal masks use a Python wrapper around unidbg's `SigSet`:

```python
signals = emulator.threads.signal_set()
signals.add(2)
signals.remove(2)
```

## Python-native worker pools

Workers may be arbitrary Python objects. Each worker is exclusively owned by
one borrower at a time.

```python
pool = pyunidbg.WorkerPool(
    create_worker,
    max_size=4,
    min_idle=1,
    idle_timeout=600,
)

with pool.borrow(timeout=5) as worker:
    result = worker.module.call_symbol("target")

result = await pool.run_async(operation, timeout=5)
pool.close()
```

Call `lease.invalidate()` before closing a lease when a worker is no longer
safe to reuse.

## State inspection

```python
report = emulator.inspect_state(
    memory_ranges=((module.base, 0x100),),
)
report.save("inspection.json")
```

Reports contain registers, loaded modules, memory maps, guest task metadata,
breakpoints, and only the explicitly requested memory ranges. They are
diagnostic exports, not restorable snapshots.

Although unidbg 0.9.9 declares `serialize(DataOutput)`, its ARM SVC memory,
syscall handler, and dynamic linker implementations throw
`UnsupportedOperationException`, and no deserializer exists. pyunidbg therefore
does not expose misleading `dump_state()` or `restore_state()` APIs.

## WeChatX acceptance harness

`examples/wechatx_decryptor.py` is a Python rewrite of the Java harness in
`/home/ujhhgtg/coding/wechatx_deobf`. It is the end-to-end acceptance target for
the binding and does not modify the source repository:

```bash
uv run --extra wechatx python examples/wechatx_decryptor.py \
  --work-dir /tmp/wechatx-python
```

The integration test verifies all 11 final outputs byte-for-byte by size and
SHA-256:

```bash
uv run --extra wechatx pytest
```
