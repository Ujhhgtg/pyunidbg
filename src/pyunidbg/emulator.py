from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from types import TracebackType
from typing import Any, Self

import jpype

from ._runtime import ensure_jvm, java_class
from .debug import Debugger, Trace
from .dvm import VM
from .filesystem import FileSystem, SyscallHandler, install_io_resolver
from .hooks import (
    BackendHooks,
    InlineHooks,
    ListenerRegistry,
    MemoryLeakTracker,
    install_system_property_provider,
    register_svc,
)
from .memory import Memory, Pointer
from .threads import GuestThreadDispatcher


@dataclass(frozen=True, slots=True)
class MemoryRegion:
    begin: int
    end: int
    virtual_address: int
    permissions: int
    offset: int
    name: str
    java: Any


class Symbol:
    def __init__(self, module: Module, java: Any):
        self._module = module
        self.java = java

    @property
    def name(self) -> str:
        return str(self.java.getName())

    @property
    def address(self) -> int:
        return int(self.java.getAddress())

    @property
    def value(self) -> int:
        return int(self.java.getValue())

    @property
    def module_name(self) -> str:
        return str(self.java.getModuleName())

    @property
    def undefined(self) -> bool:
        return bool(self.java.isUndef())

    def call(self, *args: Any) -> Any:
        return self._module._emulator._run_checked(
            lambda: self.java.call(
                self._module._emulator.java, self._module._emulator._java_args(args)
            )
        )


class RegisterContext:
    def __init__(self, emulator: AndroidEmulator, java: Any):
        self._emulator = emulator
        self.java = java

    def int_arg(self, index: int) -> int:
        return int(self.java.getIntArg(index))

    def long_arg(self, index: int) -> int:
        return int(self.java.getLongArg(index))

    def pointer_arg(self, index: int) -> Pointer | None:
        value = self.java.getPointerArg(index)
        return None if value is None else Pointer(self._emulator, int(value.peer))

    @property
    def lr(self) -> int:
        return int(self.java.getLR())

    def read_register(self, register: int) -> int:
        return int(self._emulator.backend.reg_read(int(register)))

    def write_register(self, register: int, value: int) -> None:
        self._emulator.backend.reg_write(int(register), jpype.JLong(value))

    def set_pc(self, address: int) -> None:
        arm64 = self._emulator._class("unicorn.Arm64Const")
        self.write_register(int(arm64.UC_ARM64_REG_PC), address)


class Module:
    def __init__(self, emulator: AndroidEmulator, dalvik: Any, java: Any):
        self._emulator = emulator
        self._dalvik = dalvik
        self.java = java
        self._callback_refs: list[Any] = []

    @property
    def base(self) -> int:
        return int(self.java.base)

    @property
    def name(self) -> str:
        return str(self.java.name)

    @property
    def size(self) -> int:
        return int(self.java.size)

    @property
    def path(self) -> str:
        return str(self.java.getPath())

    @property
    def file_size(self) -> int:
        return int(self.java.getFileSize())

    @property
    def base_header(self) -> int:
        return int(self.java.getBaseHeader())

    @property
    def virtual(self) -> bool:
        return bool(self.java.isVirtual())

    @property
    def force_call_init(self) -> bool:
        return bool(self.java.isForceCallInit())

    @property
    def regions(self) -> tuple[MemoryRegion, ...]:
        return tuple(
            MemoryRegion(
                begin=int(region.begin),
                end=int(region.end),
                virtual_address=int(region.virtualAddress),
                permissions=int(region.perms),
                offset=int(region.offset),
                name=str(region.getName()),
                java=region,
            )
            for region in self.java.getRegions()
        )

    @property
    def exported_symbols(self) -> tuple[Symbol, ...]:
        return tuple(Symbol(self, symbol) for symbol in self.java.getExportedSymbols())

    @property
    def needed_libraries(self) -> tuple[Module, ...]:
        return tuple(Module(self._emulator, None, module) for module in self.java.getNeededLibraries())

    def find_symbol(self, name: str, *, dependencies: bool = False) -> Symbol | None:
        raw = self.java.findSymbolByName(name, bool(dependencies))
        return None if raw is None else Symbol(self, raw)

    def closest_symbol(self, address: int, *, fast: bool = False) -> Symbol | None:
        raw = self.java.findClosestSymbolByAddress(int(address), bool(fast))
        return None if raw is None else Symbol(self, raw)

    def dependency(self, name: str) -> Module | None:
        raw = self.java.getDependencyModule(name)
        return None if raw is None else Module(self._emulator, None, raw)

    def register_symbol(self, name: str, address: int) -> None:
        self.java.registerSymbol(name, int(address))

    def add_reference(self) -> None:
        self.java.addReferenceCount()

    def decrement_reference(self) -> int:
        return int(self.java.decrementReferenceCount())

    def enable_force_call_init(self) -> None:
        self.java.setForceCallInit()

    def unload(self) -> None:
        self.java.unload(self._emulator.backend)

    def set_entry_point(self, address: int) -> None:
        self.java.setEntryPoint(int(address))

    def call_entry(self, *arguments: str) -> int:
        factory: Any = jpype.JArray(self._emulator._class("java.lang.String"))
        array = factory(arguments)
        return int(
            self._emulator._run_checked(lambda: self.java.callEntry(self._emulator.java, array))
        )

    def virtual_address_to_file_offset(self, address: int) -> int:
        return int(self.java.virtualMemoryAddressToFileOffset(int(address)))

    def set_init_listener(
        self,
        *,
        before: Callable[[Module, int, int], None] | None = None,
        after: Callable[[Module, int, int], None] | None = None,
    ) -> None:
        owner = self

        class Listener:
            def onPreCallInitFunction(self, raw_module: Any, address: int, index: int) -> None:
                if before is not None:
                    before(owner, int(address), int(index))

            def onPostCallInitFunction(self, raw_module: Any, address: int, index: int) -> None:
                if after is not None:
                    after(owner, int(address), int(index))

        impl = Listener()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.spi.InitFunctionListener"), inst=impl)
        self.java.setInitFunctionListener(proxy)
        self._callback_refs.extend((impl, proxy, before, after))

    def call_jni_on_load(self) -> None:
        if self._dalvik is None:
            raise RuntimeError("JNI_OnLoad is available only for libraries loaded through the Dalvik VM")
        self._emulator._run_checked(lambda: self._dalvik.callJNI_OnLoad(self._emulator.java))

    def call_offset(self, offset: int, *args: Any) -> Any:
        return self._emulator._run_checked(
            lambda: self.java.callFunction(
                self._emulator.java, jpype.JLong(offset), self._emulator._java_args(args)
            )
        )

    def call_symbol(self, symbol: str, *args: Any) -> Any:
        return self._emulator._run_checked(
            lambda: self.java.callFunction(
                self._emulator.java, symbol, self._emulator._java_args(args)
            )
        )

    def add_breakpoint(self, offset: int, callback: Callable[[AndroidEmulator, int, RegisterContext], bool]) -> Any:
        module = self

        class Callback:
            def onHit(self, raw_emulator: Any, address: int) -> bool:
                context = RegisterContext(module._emulator, raw_emulator.getContext())
                return bool(callback(module._emulator, int(address), context))

        impl = Callback()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.debugger.BreakPointCallback"), inst=impl)
        breakpoint = self._emulator.java.attach().addBreakPoint(self.java, int(offset), proxy)
        self._callback_refs.extend((impl, proxy, callback))
        return breakpoint

    def breakpoint(self, offset: int) -> Callable[[Callable[..., bool]], Callable[..., bool]]:
        def decorate(callback: Callable[..., bool]) -> Callable[..., bool]:
            self.add_breakpoint(offset, callback)
            return callback

        return decorate


class AndroidEmulator:
    def __init__(
        self,
        process_name: str,
        *,
        api_level: int = 23,
        root_dir: str | Path | None = None,
        apk: str | Path | None = None,
        verbose: bool = False,
    ):
        ensure_jvm()
        self._closed = False
        self._callback_error: BaseException | None = None
        self._classes: dict[str, Any] = {}
        builder = self._class("com.github.unidbg.linux.android.AndroidEmulatorBuilder").for64Bit()
        builder.setProcessName(process_name)
        file_class = self._class("java.io.File")
        if root_dir is not None:
            builder.setRootDir(file_class(str(Path(root_dir).resolve())))
        self.java = builder.build()
        self.backend = self.java.getBackend()
        raw_memory = self.java.getMemory()
        raw_memory.setLibraryResolver(
            self._class("com.github.unidbg.linux.android.AndroidResolver")(int(api_level))
        )
        self.memory = Memory(self, raw_memory)
        raw_vm = (
            self.java.createDalvikVM(file_class(str(Path(apk).resolve())))
            if apk is not None
            else self.java.createDalvikVM()
        )
        raw_vm.setVerbose(bool(verbose))
        self.vm = VM(self, raw_vm)
        self.filesystem = FileSystem(self, self.java.getFileSystem())
        self.syscalls = SyscallHandler(self, self.java.getSyscallHandler())
        self.threads = GuestThreadDispatcher(self)
        self._module_refs: list[Module] = []
        self._callback_refs: list[Any] = []
        self._mcp_server: Any = None
        self.hooks = BackendHooks(self)
        self.listeners = ListenerRegistry(self)
        self.inline = InlineHooks(self)

    def _class(self, name: str) -> Any:
        value = self._classes.get(name)
        if value is None:
            value = java_class(name)
            self._classes[name] = value
        return value

    def _java_args(self, args: tuple[Any, ...]) -> Any:
        return self.vm._object_array(args)

    def _capture_callback_error(self, error: BaseException) -> None:
        if self._callback_error is None:
            self._callback_error = error

    def _raise_callback_error(self) -> None:
        error = self._callback_error
        self._callback_error = None
        if error is not None:
            raise error

    def _run_checked(self, callback: Callable[[], Any]) -> Any:
        try:
            result = callback()
        except BaseException:
            if self._callback_error is not None:
                self._raise_callback_error()
            raise
        self._raise_callback_error()
        return result

    def load_library(self, path: str | Path, *, call_jni_on_load: bool = False) -> Module:
        file_class = self._class("java.io.File")
        dalvik = self._run_checked(
            lambda: self.vm.java.loadLibrary(file_class(str(Path(path).resolve())), False)
        )
        module = Module(self, dalvik, dalvik.getModule())
        self._module_refs.append(module)
        if call_jni_on_load:
            module.call_jni_on_load()
        return module

    def add_breakpoint(
        self,
        address: int,
        callback: Callable[[AndroidEmulator, int, RegisterContext], bool],
    ) -> Any:
        owner = self

        class Callback:
            def onHit(self, raw_emulator: Any, hit_address: int) -> bool:
                context = RegisterContext(owner, raw_emulator.getContext())
                return bool(callback(owner, int(hit_address), context))

        impl = Callback()
        proxy = jpype.JProxy(self._class("com.github.unidbg.debugger.BreakPointCallback"), inst=impl)
        breakpoint = self.java.attach().addBreakPoint(int(address), proxy)
        self._callback_refs.extend((impl, proxy, callback))
        return breakpoint

    def debugger(self, kind: str = "console") -> Debugger:
        kinds = {
            "console": "CONSOLE",
            "gdb": "GDB_SERVER",
            "android": "ANDROID_SERVER_V7",
        }
        try:
            enum_name = kinds[kind.lower()]
        except KeyError as exc:
            raise ValueError(f"unknown debugger kind: {kind!r}") from exc
        enum = self._class("com.github.unidbg.debugger.DebuggerType").valueOf(enum_name)
        return Debugger(self, self.java.attach(enum))

    def trace_read(
        self,
        callback: Callable[[AndroidEmulator, int, bytes, str], bool] | None = None,
        *,
        begin: int | None = None,
        end: int | None = None,
    ) -> Trace:
        if callback is None:
            last = int(end) if end is not None else 0x7FFFFFFFFFFFFFFF
            raw = self.java.traceRead() if begin is None else self.java.traceRead(int(begin), last)
            return Trace(self, raw)
        owner = self

        class Listener:
            def onRead(self, raw_emulator: Any, address: int, data: Any, label: str) -> bool:
                return bool(callback(owner, int(address), bytes(data), str(label)))

        impl = Listener()
        proxy = jpype.JProxy(self._class("com.github.unidbg.listener.TraceReadListener"), inst=impl)
        raw = self.java.traceRead(int(begin or 0), int(end if end is not None else 0x7FFFFFFFFFFFFFFF), proxy)
        return Trace(self, raw, (impl, proxy, callback))

    def trace_write(
        self,
        callback: Callable[[AndroidEmulator, int, int, int], bool] | None = None,
        *,
        begin: int | None = None,
        end: int | None = None,
    ) -> Trace:
        if callback is None:
            last = int(end) if end is not None else 0x7FFFFFFFFFFFFFFF
            raw = self.java.traceWrite() if begin is None else self.java.traceWrite(int(begin), last)
            return Trace(self, raw)
        owner = self

        class Listener:
            def onWrite(self, raw_emulator: Any, address: int, size: int, value: int) -> bool:
                return bool(callback(owner, int(address), int(size), int(value)))

        impl = Listener()
        proxy = jpype.JProxy(self._class("com.github.unidbg.listener.TraceWriteListener"), inst=impl)
        raw = self.java.traceWrite(int(begin or 0), int(end if end is not None else 0x7FFFFFFFFFFFFFFF), proxy)
        return Trace(self, raw, (impl, proxy, callback))

    def trace_code(
        self,
        callback: Callable[[AndroidEmulator, int, Any], None] | None = None,
        *,
        begin: int | None = None,
        end: int | None = None,
    ) -> Trace:
        if callback is None:
            last = int(end) if end is not None else 0x7FFFFFFFFFFFFFFF
            raw = self.java.traceCode() if begin is None else self.java.traceCode(int(begin), last)
            return Trace(self, raw)
        owner = self

        class Listener:
            def onInstruction(self, raw_emulator: Any, address: int, instruction: Any) -> None:
                callback(owner, int(address), instruction)

        impl = Listener()
        proxy = jpype.JProxy(self._class("com.github.unidbg.listener.TraceCodeListener"), inst=impl)
        raw = self.java.traceCode(int(begin or 0), int(end if end is not None else 0x7FFFFFFFFFFFFFFF), proxy)
        return Trace(self, raw, (impl, proxy, callback))

    def trace_system_memory_writes(
        self,
        begin: int,
        end: int,
        callback: Callable[[AndroidEmulator, int, bytes], None],
    ) -> None:
        owner = self

        class Listener:
            def onWrite(self, raw_emulator: Any, address: int, data: Any) -> None:
                callback(owner, int(address), bytes(data))

        impl = Listener()
        proxy = jpype.JProxy(
            self._class("com.github.unidbg.listener.TraceSystemMemoryWriteListener"), inst=impl
        )
        self.java.setTraceSystemMemoryWrite(int(begin), int(end), proxy)
        self._callback_refs.extend((impl, proxy, callback))

    def add_io_resolver(self, callback: Callable[[AndroidEmulator, str, int], Any]) -> Any:
        return install_io_resolver(self, callback)

    def call_address(self, address: int, *args: Any) -> Any:
        numbers = []
        for value in args:
            if hasattr(value, "java"):
                value = value.java
            if isinstance(value, int):
                value = jpype.JLong(value)
            numbers.append(value)
        factory: Any = jpype.JArray(self._class("java.lang.Number"))
        array = factory(numbers)
        return self._run_checked(lambda: self.java.eFunc(jpype.JLong(address), array))

    def register_svc(
        self,
        callback: Callable[[AndroidEmulator], int],
        *,
        name: str = "pyunidbg",
        before: Callable[[AndroidEmulator], None] | None = None,
        after: Callable[[AndroidEmulator], None] | None = None,
    ) -> Any:
        return register_svc(self, callback, name=name, before=before, after=after)

    def set_system_property_provider(
        self, callback: Callable[[str], str | None]
    ) -> Any:
        return install_system_property_provider(self, callback)

    def track_memory_leaks(self) -> MemoryLeakTracker:
        return MemoryLeakTracker(self, self.java.traceMemoryLeaks())

    def inspect_state(
        self,
        *,
        memory_ranges: tuple[tuple[int, int], ...] = (),
        max_capture_size: int = 1024 * 1024,
    ) -> Any:
        from .serialization import inspect_emulator_state

        return self._run_checked(
            lambda: inspect_emulator_state(
                self,
                memory_ranges=memory_ranges,
                max_capture_size=max_capture_size,
            )
        )

    def mcp(
        self,
        *,
        host: str = "127.0.0.1",
        port: int = 9239,
        allow_remote: bool = False,
        event_limit: int = 1024,
    ) -> Any:
        from .mcp import PyUnidbgMcpServer

        if self._mcp_server is not None:
            raise RuntimeError("this emulator already owns an MCP server")
        self._mcp_server = PyUnidbgMcpServer(
            self,
            host=host,
            port=port,
            allow_remote=allow_remote,
            event_limit=event_limit,
        )
        return self._mcp_server

    def close(self) -> None:
        if not self._closed:
            if self._mcp_server is not None:
                self._mcp_server.stop()
            self.java.close()
            self._closed = True

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
