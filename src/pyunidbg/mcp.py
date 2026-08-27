from __future__ import annotations

import asyncio
import functools
import inspect
import threading
import time
from collections import deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self, TypeVar

import jpype
import uvicorn
from mcp.server.mcpserver import MCPServer as ProtocolServer

from .memory import Allocation

T = TypeVar("T")


@dataclass(frozen=True, slots=True)
class McpEvent:
    sequence: int
    kind: str
    data: dict[str, Any]
    timestamp: float


class EmulatorController:
    def __init__(self, emulator: Any, *, event_limit: int = 1024):
        self.emulator = emulator
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pyunidbg-mcp")
        self._events: deque[McpEvent] = deque(maxlen=event_limit)
        self._event_condition = threading.Condition()
        self._sequence = 0
        self._closed = False
        self._pause_condition = threading.Condition()
        self._paused = False
        self._continue = False

    async def call(self, function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        if self._closed:
            raise RuntimeError("MCP emulator controller is closed")
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(
            self._executor, functools.partial(function, *args, **kwargs)
        )

    def publish(self, kind: str, **data: Any) -> McpEvent:
        with self._event_condition:
            self._sequence += 1
            event = McpEvent(self._sequence, kind, data, time.time())
            self._events.append(event)
            self._event_condition.notify_all()
            return event

    def poll(self, after: int = 0, timeout_ms: int = 0) -> list[dict[str, Any]]:
        deadline = time.monotonic() + timeout_ms / 1000
        with self._event_condition:
            while not any(event.sequence > after for event in self._events):
                remaining = deadline - time.monotonic()
                if timeout_ms <= 0 or remaining <= 0:
                    break
                self._event_condition.wait(remaining)
            return [
                {
                    "sequence": event.sequence,
                    "event": event.kind,
                    "timestamp": event.timestamp,
                    **event.data,
                }
                for event in self._events
                if event.sequence > after
            ]

    def breakpoint_wait(self, address: int) -> None:
        with self._pause_condition:
            self._paused = True
            self._continue = False
            self.publish("breakpoint_hit", address=f"0x{address:x}")
            while not self._continue and not self._closed:
                self._pause_condition.wait()
            self._paused = False
            self._continue = False

    def continue_execution(self) -> bool:
        with self._pause_condition:
            if not self._paused:
                return False
            self._continue = True
            self._pause_condition.notify_all()
            self.publish("execution_continued")
            return True

    @property
    def paused(self) -> bool:
        with self._pause_condition:
            return self._paused

    def close(self) -> None:
        if not self._closed:
            self._closed = True
            with self._pause_condition:
                self._continue = True
                self._pause_condition.notify_all()
            self._executor.shutdown(wait=True, cancel_futures=True)


class PyUnidbgMcpServer:
    def __init__(
        self,
        emulator: Any,
        *,
        host: str = "127.0.0.1",
        port: int = 9239,
        allow_remote: bool = False,
        event_limit: int = 1024,
    ):
        if host not in {"127.0.0.1", "localhost", "::1"} and not allow_remote:
            raise ValueError("remote MCP binding requires allow_remote=True")
        self.emulator = emulator
        self.host = host
        self.port = int(port)
        self.url = f"http://{host}:{port}/mcp"
        self.controller = EmulatorController(emulator, event_limit=event_limit)
        self.protocol = ProtocolServer(
            "pyunidbg",
            description="Python-native Android ARM64 unidbg debugger",
            instructions="Inspect and control an Android ARM64 emulator. Addresses may be integers or hexadecimal strings.",
        )
        self._uvicorn: uvicorn.Server | None = None
        self._thread: threading.Thread | None = None
        self._allocations: dict[int, Allocation] = {}
        self._breakpoints: dict[int, Any] = {}
        self._traces: dict[str, Any] = {}
        self._step_hooks: list[Any] = []
        self._started = False
        self._closed = False
        self._register_tools()

    @staticmethod
    def _address(value: int | str) -> int:
        return int(value, 0) if isinstance(value, str) else int(value)

    async def _call(self, function: Callable[..., T], *args: Any, **kwargs: Any) -> T:
        return await self.controller.call(function, *args, **kwargs)

    def _step_code(self, predicate: Callable[[int], bool]) -> bool:
        if not self.controller.paused:
            return False
        fired = [False]

        def callback(_emulator: Any, address: int, _size: int, _data: Any) -> None:
            if not fired[0] and predicate(address):
                fired[0] = True
                self.controller.breakpoint_wait(address)

        self._step_hooks.append(self.emulator.hooks.code(callback))
        return self.controller.continue_execution()

    def _step_block(self) -> bool:
        if not self.controller.paused:
            return False
        blocks = [0]

        def callback(_emulator: Any, address: int, _size: int, _data: Any) -> None:
            blocks[0] += 1
            if blocks[0] >= 2:
                self.controller.breakpoint_wait(address)

        self._step_hooks.append(self.emulator.hooks.block(callback))
        return self.controller.continue_execution()

    def _register_tools(self) -> None:
        tool = self.protocol.tool

        @tool()
        async def check_connection() -> dict[str, Any]:
            """Return emulator identity, backend, execution state, and module count."""
            return await self._call(
                lambda: {
                    "family": "Android",
                    "architecture": "ARM64",
                    "backend": str(self.emulator.backend.getClass().getSimpleName()),
                    "process": str(self.emulator.java.getProcessName()),
                    "running": bool(self.emulator.java.isRunning()),
                    "paused": self.controller.paused,
                    "modules": len(self.emulator.memory.java.getLoadedModules()),
                }
            )

        @tool()
        async def list_modules() -> list[dict[str, Any]]:
            """List loaded native modules."""
            def operation() -> list[dict[str, Any]]:
                return [
                    {
                        "name": str(module.name),
                        "base": f"0x{int(module.base):x}",
                        "size": int(module.size),
                        "path": str(module.getPath()),
                    }
                    for module in self.emulator.memory.java.getLoadedModules()
                ]
            return await self._call(operation)

        @tool()
        async def get_module_info(name: str) -> dict[str, Any]:
            """Get detailed information for a loaded module."""
            def operation() -> dict[str, Any]:
                raw = self.emulator.memory.java.findModule(name)
                if raw is None:
                    raise ValueError(f"module not found: {name}")
                return {
                    "name": str(raw.name), "base": f"0x{int(raw.base):x}",
                    "size": int(raw.size), "path": str(raw.getPath()),
                    "exports": len(raw.getExportedSymbols()),
                    "dependencies": [str(item.name) for item in raw.getNeededLibraries()],
                }
            return await self._call(operation)

        @tool()
        async def list_exports(module_name: str, filter: str = "") -> list[dict[str, Any]]:
            """List exported symbols, optionally filtered by name."""
            def operation() -> list[dict[str, Any]]:
                module = self.emulator.memory.java.findModule(module_name)
                if module is None:
                    raise ValueError(f"module not found: {module_name}")
                return [
                    {"name": str(symbol.getName()), "address": f"0x{int(symbol.getAddress()):x}"}
                    for symbol in module.getExportedSymbols()
                    if filter.lower() in str(symbol.getName()).lower()
                ]
            return await self._call(operation)

        @tool()
        async def find_symbol(name: str, module_name: str = "") -> dict[str, Any] | None:
            """Find an exported symbol by name."""
            def operation() -> dict[str, Any] | None:
                modules = (
                    [self.emulator.memory.java.findModule(module_name)]
                    if module_name else list(self.emulator.memory.java.getLoadedModules())
                )
                for module in modules:
                    if module is None: continue
                    symbol = module.findSymbolByName(name, False)
                    if symbol is not None:
                        return {"name": name, "module": str(module.name), "address": f"0x{int(symbol.getAddress()):x}"}
                return None
            return await self._call(operation)

        @tool()
        async def list_memory_map() -> list[dict[str, Any]]:
            """List guest memory mappings."""
            return await self._call(lambda: [
                {"base": f"0x{int(item.base):x}", "size": int(item.size), "protection": int(item.prot)}
                for item in self.emulator.memory.java.getMemoryMap()
            ])

        @tool()
        async def read_memory(address: int | str, size: int) -> dict[str, Any]:
            """Read guest memory and return hexadecimal bytes."""
            data = await self._call(self.emulator.memory.read, self._address(address), int(size))
            return {"address": f"0x{self._address(address):x}", "size": len(data), "hex": data.hex()}

        @tool()
        async def write_memory(address: int | str, hex_data: str) -> dict[str, Any]:
            """Write hex-encoded bytes to guest memory."""
            data = bytes.fromhex(hex_data)
            await self._call(self.emulator.memory.write, self._address(address), data)
            return {"written": len(data)}

        @tool()
        async def read_string(address: int | str, max_length: int = 4096) -> str:
            """Read a null-terminated UTF-8 string."""
            def operation() -> str:
                data = self.emulator.memory.read(self._address(address), max_length)
                return data.split(b"\0", 1)[0].decode("utf-8", errors="replace")
            return await self._call(operation)

        @tool()
        async def read_pointer(address: int | str) -> str:
            """Read one ARM64 pointer."""
            value = await self._call(self.emulator.memory.pointer(self._address(address)).read_u64)
            return f"0x{value:x}"

        @tool()
        async def read_typed(address: int | str, type: str = "uint64") -> Any:
            """Read uint8, int32, uint32, int64, uint64, float, double, or pointer."""
            import struct
            formats = {"uint8": "<B", "int32": "<i", "uint32": "<I", "int64": "<q", "uint64": "<Q", "pointer": "<Q", "float": "<f", "double": "<d"}
            if type not in formats: raise ValueError(f"unsupported type: {type}")
            fmt = formats[type]; size = struct.calcsize(fmt)
            data = await self._call(self.emulator.memory.read, self._address(address), size)
            value = struct.unpack(fmt, data)[0]
            return f"0x{value:x}" if type == "pointer" else value

        @tool()
        async def search_memory(hex_pattern: str, max_results: int = 100) -> list[str]:
            """Search readable mappings for an exact byte pattern."""
            pattern = bytes.fromhex(hex_pattern)
            def operation() -> list[str]:
                found: list[str] = []
                for mapping in self.emulator.memory.java.getMemoryMap():
                    if not (int(mapping.prot) & 1): continue
                    try: data = self.emulator.memory.read(int(mapping.base), int(mapping.size))
                    except Exception: continue
                    start = 0
                    while len(found) < max_results:
                        index = data.find(pattern, start)
                        if index < 0: break
                        found.append(f"0x{int(mapping.base) + index:x}"); start = index + 1
                return found
            return await self._call(operation)

        @tool()
        async def allocate_memory(size: int, protection: int = 3, hex_data: str = "") -> dict[str, Any]:
            """Allocate tracked guest memory."""
            def operation() -> dict[str, Any]:
                allocation = self.emulator.memory.malloc(int(size))
                address = int(allocation.pointer)
                if hex_data: allocation.pointer.write(bytes.fromhex(hex_data))
                self._allocations[address] = allocation
                return {"address": f"0x{address:x}", "size": int(size), "protection": protection}
            return await self._call(operation)

        @tool()
        async def free_memory(address: int | str) -> bool:
            """Free memory previously allocated by this MCP server."""
            def operation() -> bool:
                allocation = self._allocations.pop(self._address(address), None)
                if allocation is None: return False
                allocation.free(); return True
            return await self._call(operation)

        @tool()
        async def list_allocations() -> list[dict[str, Any]]:
            """List memory blocks owned by this MCP server."""
            return await self._call(
                lambda: [{"address": f"0x{address:x}"} for address in self._allocations]
            )

        @tool()
        async def get_register(register: int) -> str:
            """Read an ARM64 Unicorn register by numeric identifier."""
            value = await self._call(self.emulator.backend.reg_read, int(register))
            return f"0x{int(value):x}"

        @tool()
        async def set_register(register: int, value: int | str) -> bool:
            """Write an ARM64 Unicorn register by numeric identifier."""
            await self._call(self.emulator.backend.reg_write, int(register), jpype.JLong(self._address(value)))
            return True

        @tool()
        async def get_registers() -> dict[str, str]:
            """Read X0-X30, SP, PC, and NZCV."""
            constants = self.emulator._class("unicorn.Arm64Const")
            names = [f"X{i}" for i in range(31)] + ["SP", "PC", "NZCV"]
            result = {}
            for name in names:
                reg = int(getattr(constants, f"UC_ARM64_REG_{name}"))
                result[name.lower()] = f"0x{int(await self._call(self.emulator.backend.reg_read, reg)):x}"
            return result

        @tool()
        async def get_threads() -> list[dict[str, Any]]:
            """List emulator dispatcher tasks."""
            def operation() -> list[dict[str, Any]]:
                dispatcher = self.emulator.java.getThreadDispatcher()
                return [
                    {"description": str(task), "class": str(task.getClass().getSimpleName())}
                    for task in dispatcher.getTaskList()
                ]
            return await self._call(operation)

        @tool()
        async def get_callstack(max_frames: int = 64) -> list[dict[str, str]]:
            """Return the current native call stack."""
            def operation() -> list[dict[str, str]]:
                return [
                    {"ip": f"0x{int(frame.ip.peer):x}", "fp": f"0x{int(frame.fp.peer):x}"}
                    for frame in self.emulator.java.getUnwinder().getFrames(int(max_frames))
                ]
            return await self._call(operation)

        @tool()
        async def read_std_string(address: int | str) -> str:
            """Read a libc++ std::string using its ARM64 SSO layout."""
            def operation() -> str:
                pointer = self.emulator.memory.pointer(self._address(address))
                header = pointer.read(24)
                if header[0] & 1:
                    length = int.from_bytes(header[8:16], "little")
                    data_address = int.from_bytes(header[16:24], "little")
                    data = self.emulator.memory.read(data_address, length)
                else:
                    length = header[0] >> 1
                    data = header[1 : 1 + length]
                return data.decode("utf-8", errors="replace")
            return await self._call(operation)

        @tool()
        async def disassemble(address: int | str, size: int = 32) -> list[dict[str, Any]]:
            """Disassemble ARM64 instructions."""
            def operation() -> list[dict[str, Any]]:
                instructions = self.emulator.java.disassemble(jpype.JLong(self._address(address)), int(size), jpype.JLong(0))
                return [{"address": f"0x{int(i.getAddress()):x}", "mnemonic": str(i.getMnemonic()), "operands": str(i.getOpStr()), "bytes": bytes(i.getBytes()).hex()} for i in instructions]
            return await self._call(operation)

        @tool()
        async def assemble(instructions: str, address: int | str = 0) -> dict[str, Any]:
            """Assemble ARM64 instructions and return machine-code bytes."""
            def operation() -> dict[str, Any]:
                architecture = self.emulator._class("keystone.KeystoneArchitecture").Arm64
                mode = self.emulator._class("keystone.KeystoneMode").LittleEndian
                assembler = self.emulator._class("keystone.Keystone")(architecture, mode)
                try:
                    encoded = assembler.assemble(instructions, self._address(address))
                    return {"hex": bytes(encoded.getMachineCode()).hex(), "statements": int(encoded.getNumberOfStatements())}
                finally:
                    assembler.close()
            return await self._call(operation)

        @tool()
        async def patch(address: int | str, hex_data: str) -> bool:
            """Patch raw machine-code bytes."""
            await self._call(self.emulator.memory.write, self._address(address), bytes.fromhex(hex_data)); return True

        @tool()
        async def call_symbol(module_name: str, symbol: str, arguments: list[int] | None = None) -> int:
            """Call an exported native function with integer arguments."""
            def operation() -> int:
                raw = self.emulator.memory.java.findModule(module_name)
                if raw is None: raise ValueError(f"module not found: {module_name}")
                from .emulator import Module
                return int(Module(self.emulator, None, raw).call_symbol(symbol, *(arguments or [])))
            return await self._call(operation)

        @tool()
        async def call_function(address: int | str, arguments: list[int] | None = None) -> int:
            """Call a native function by absolute address with integer arguments."""
            return int(await self._call(self.emulator.call_address, self._address(address), *(arguments or [])))

        @tool()
        async def add_breakpoint(address: int | str) -> bool:
            """Add a Python-managed pausing breakpoint."""
            target = self._address(address)
            def operation() -> bool:
                if target in self._breakpoints: return False
                self._breakpoints[target] = self.emulator.add_breakpoint(
                    target, lambda _emulator, hit, _context: self.controller.breakpoint_wait(hit) or True
                )
                return True
            return await self._call(operation)

        @tool()
        async def add_breakpoint_by_offset(module_name: str, offset: int | str) -> bool:
            """Add a breakpoint at module base plus offset."""
            raw = await self._call(self.emulator.memory.java.findModule, module_name)
            if raw is None: raise ValueError(f"module not found: {module_name}")
            return await add_breakpoint(f"0x{int(raw.base) + self._address(offset):x}")

        @tool()
        async def add_breakpoint_by_symbol(module_name: str, symbol: str) -> bool:
            """Add a breakpoint at an exported symbol."""
            def resolve() -> int:
                raw = self.emulator.memory.java.findModule(module_name)
                if raw is None: raise ValueError(f"module not found: {module_name}")
                found = raw.findSymbolByName(symbol, False)
                if found is None: raise ValueError(f"symbol not found: {symbol}")
                return int(found.getAddress())
            return await add_breakpoint(await self._call(resolve))

        @tool()
        async def list_breakpoints() -> list[str]:
            """List Python-managed breakpoint addresses."""
            return await self._call(
                lambda: [f"0x{address:x}" for address in self._breakpoints]
            )

        @tool()
        async def remove_breakpoint(address: int | str) -> bool:
            """Remove a Python-managed breakpoint."""
            target = self._address(address)
            removed = bool(await self._call(self.emulator.java.attach().removeBreakPoint, target))
            if removed: self._breakpoints.pop(target, None)
            return removed

        @tool()
        async def continue_execution() -> bool:
            """Continue execution paused at a Python-managed breakpoint."""
            return self.controller.continue_execution()

        @tool()
        async def step_into(count: int = 1) -> bool:
            """Execute a number of ARM64 instructions and pause again."""
            remaining = [max(1, int(count))]
            return await self._call(
                self._step_code,
                lambda _address: not (
                    remaining.__setitem__(0, remaining[0] - 1) or remaining[0]
                ),
            )

        @tool()
        async def step_over() -> bool:
            """Pause at the next sequential ARM64 instruction."""
            if not self.controller.paused: return False
            pc_reg = int(self.emulator._class("unicorn.Arm64Const").UC_ARM64_REG_PC)
            pc = int(await self._call(self.emulator.backend.reg_read, pc_reg))
            target = pc + 4
            await self._call(
                lambda: self._breakpoints.__setitem__(
                    target,
                    self.emulator.add_breakpoint(
                        target,
                        lambda _emulator, hit, _context: self.controller.breakpoint_wait(hit) or True,
                    ),
                )
            )
            return self.controller.continue_execution()

        @tool()
        async def next_block() -> bool:
            """Continue to the next basic block and pause."""
            return await self._call(self._step_block)

        @tool()
        async def step_until_mnemonic(mnemonic: str) -> bool:
            """Continue until an instruction with the requested mnemonic."""
            expected = mnemonic.lower()
            def matches(address: int) -> bool:
                try:
                    instruction = self.emulator.java.disassemble(jpype.JLong(address), 4, jpype.JLong(0))[0]
                    return str(instruction.getMnemonic()).lower() == expected
                except Exception:
                    return False
            return await self._call(self._step_code, matches)

        @tool()
        async def step_out() -> bool:
            """Continue until the next ARM64 ret instruction."""
            return await step_until_mnemonic("ret")

        @tool()
        async def trace_read(begin: int | str, end: int | str) -> bool:
            """Start memory-read tracing and publish trace_read events."""
            def operation() -> bool:
                if "read" in self._traces: self._traces.pop("read").stop()
                self._traces["read"] = self.emulator.trace_read(
                    lambda _emulator, address, data, label: self.controller.publish(
                        "trace_read", address=f"0x{address:x}", hex=data.hex(), label=label
                    ) is not None, begin=self._address(begin), end=self._address(end)
                )
                return True
            return await self._call(operation)

        @tool()
        async def trace_write(begin: int | str, end: int | str) -> bool:
            """Start memory-write tracing and publish trace_write events."""
            def operation() -> bool:
                if "write" in self._traces: self._traces.pop("write").stop()
                self._traces["write"] = self.emulator.trace_write(
                    lambda _emulator, address, size, value: self.controller.publish(
                        "trace_write", address=f"0x{address:x}", size=size, value=f"0x{value:x}"
                    ) is not None, begin=self._address(begin), end=self._address(end)
                )
                return True
            return await self._call(operation)

        @tool()
        async def trace_code(begin: int | str, end: int | str) -> bool:
            """Start ARM64 instruction tracing and publish trace_code events."""
            def operation() -> bool:
                if "code" in self._traces: self._traces.pop("code").stop()
                self._traces["code"] = self.emulator.trace_code(
                    lambda _emulator, address, instruction: self.controller.publish(
                        "trace_code", address=f"0x{address:x}", mnemonic=str(instruction.getMnemonic()), operands=str(instruction.getOpStr())
                    ), begin=self._address(begin), end=self._address(end)
                )
                return True
            return await self._call(operation)

        @tool()
        async def stop_trace(kind: str = "all") -> bool:
            """Stop read, write, code, or all active traces."""
            def operation() -> bool:
                names = list(self._traces) if kind == "all" else [kind]
                for name in names:
                    trace = self._traces.pop(name, None)
                    if trace is not None: trace.stop()
                return True
            return await self._call(operation)

        @tool()
        async def poll_events(after: int = 0, timeout_ms: int = 0) -> list[dict[str, Any]]:
            """Poll breakpoint, execution, tracing, and custom events."""
            return await asyncio.to_thread(self.controller.poll, after, timeout_ms)

    def tool(self, *args: Any, **kwargs: Any) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        protocol_decorator = self.protocol.tool(*args, **kwargs)
        def decorate(function: Callable[..., Any]) -> Callable[..., Any]:
            if inspect.iscoroutinefunction(function):
                protocol_decorator(function)
                return function
            @functools.wraps(function)
            async def wrapped(*fn_args: Any, **fn_kwargs: Any) -> Any:
                return await self._call(function, *fn_args, **fn_kwargs)
            protocol_decorator(wrapped)
            return function
        return decorate

    def asgi_app(self) -> Any:
        return self.protocol.streamable_http_app(host=self.host)

    def client_config(self, name: str = "pyunidbg") -> dict[str, Any]:
        return {"mcpServers": {name: {"type": "http", "url": self.url}}}

    def start(self) -> PyUnidbgMcpServer:
        if self._closed:
            raise RuntimeError("MCP server is closed; create a new server")
        if self._started: return self
        app = self.asgi_app()
        config = uvicorn.Config(app, host=self.host, port=self.port, log_level="warning")
        self._uvicorn = uvicorn.Server(config)
        self._thread = threading.Thread(target=self._uvicorn.run, name="pyunidbg-mcp-http", daemon=True)
        self._thread.start()
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if self._uvicorn.started:
                self._started = True; return self
            if not self._thread.is_alive(): break
            time.sleep(0.01)
        self.stop(); raise RuntimeError(f"MCP server failed to start on {self.host}:{self.port}")

    def stop(self) -> None:
        if self._closed:
            return
        if self._uvicorn is not None:
            self._uvicorn.should_exit = True
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=10)
        for allocation in list(self._allocations.values()):
            try: allocation.free()
            except Exception: pass
        self._allocations.clear()
        for trace in list(self._traces.values()):
            try: trace.stop()
            except Exception: pass
        self._traces.clear()
        for hook in self._step_hooks:
            try: hook.close()
            except Exception: pass
        self._step_hooks.clear()
        self.controller.close()
        self._uvicorn = None; self._thread = None; self._started = False
        self._closed = True
        if getattr(self.emulator, "_mcp_server", None) is self:
            self.emulator._mcp_server = None

    @property
    def running(self) -> bool:
        return self._started

    def __enter__(self) -> Self:
        self.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.stop()
