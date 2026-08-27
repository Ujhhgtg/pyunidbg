from __future__ import annotations

from pathlib import Path
from typing import Any, Callable, Iterable

import jpype


class Trace:
    def __init__(self, emulator: Any, java: Any, references: tuple[Any, ...] = ()):
        self._emulator = emulator
        self.java = java
        self._references = references
        self._stream: Any = None

    def redirect(self, path: str | Path) -> Trace:
        stream = self._emulator._class("java.io.PrintStream")(str(Path(path)))
        self.java.setRedirect(stream)
        self._stream = stream
        return self

    def stop(self) -> None:
        self.java.stopTrace()
        if self._stream is not None:
            self._stream.close()
            self._stream = None

    def __enter__(self) -> Trace:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.stop()


class Breakpoint:
    def __init__(self, java: Any):
        self.java = java

    @property
    def temporary(self) -> bool:
        return bool(self.java.isTemporary())

    @temporary.setter
    def temporary(self, value: bool) -> None:
        self.java.setTemporary(bool(value))

    @property
    def thumb(self) -> bool:
        return bool(self.java.isThumb())


class Debugger:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java
        self._references: list[Any] = []

    @property
    def debugging(self) -> bool:
        return bool(self.java.isDebugging())

    @property
    def has_runnable(self) -> bool:
        return bool(self.java.hasRunnable())

    @property
    def breakpoints(self) -> dict[int, Breakpoint]:
        return {int(entry.getKey()): Breakpoint(entry.getValue()) for entry in self.java.getBreakPoints().entrySet()}

    def remove_breakpoint(self, address: int) -> bool:
        return bool(self.java.removeBreakPoint(int(address)))

    def disassemble_block(self, address: int, *, thumb: bool = False) -> None:
        self.java.disassembleBlock(self._emulator.java, int(address), bool(thumb))

    def set_debug_filter(self, callback: Callable[[Any, Any], bool] | None) -> None:
        if callback is None:
            self.java.setDebugListener(None)
            return

        owner = self

        class Listener:
            def canDebug(self, raw_emulator: Any, history: Any) -> bool:
                return bool(callback(owner._emulator, history))

        impl = Listener()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.debugger.DebugListener"), inst=impl)
        self.java.setDebugListener(proxy)
        self._references.extend((impl, proxy, callback))

    def trace_function_calls(
        self,
        on_call: Callable[[Any, int, int], None],
        post_call: Callable[[Any, int, int, tuple[int, ...]], None] | None = None,
        *,
        module: Any = None,
    ) -> None:
        owner = self

        class Delegate:
            def onCall(self, raw_emulator: Any, caller: int, function: int) -> None:
                on_call(owner._emulator, int(caller), int(function))

            def postCall(self, raw_emulator: Any, caller: int, function: int, args: Any) -> None:
                if post_call is not None:
                    post_call(owner._emulator, int(caller), int(function), tuple(int(arg) for arg in args))

        impl = Delegate()
        interface = self._emulator._class("io.pyunidbg.bridge.FunctionCallDelegate")
        proxy = jpype.JProxy(interface, inst=impl)
        listener = self._emulator._class("io.pyunidbg.bridge.BridgeFunctionCallListener")(proxy)
        if module is None:
            self.java.traceFunctionCall(listener)
        else:
            self.java.traceFunctionCall(module.java, listener)
        self._references.extend((impl, proxy, listener, on_call, post_call))

    def run(self, callback: Callable[[tuple[str, ...]], Any]) -> Any:
        class Runnable:
            def runWithArgs(self, args: Any) -> Any:
                return callback(tuple(str(arg) for arg in args))

        impl = Runnable()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.debugger.DebugRunnable"), inst=impl)
        self._references.extend((impl, proxy, callback))
        return self.java.run(proxy)

    def add_mcp_tool(self, name: str, description: str, *arguments: str) -> None:
        string_array = jpype.JArray(self._emulator._class("java.lang.String"))(arguments)
        self.java.addMcpTool(name, description, string_array)

    def close(self) -> None:
        self.java.close()
