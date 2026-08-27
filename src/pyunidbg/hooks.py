from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, IntFlag
from pathlib import Path
from typing import Any, Callable

import jpype

from .memory import Pointer


class MemoryHookMask(IntFlag):
    READ_UNMAPPED = 16
    WRITE_UNMAPPED = 32
    FETCH_UNMAPPED = 64
    READ_PROTECTED = 128
    WRITE_PROTECTED = 256
    FETCH_PROTECTED = 512
    INVALID = 1008


class MemoryEvent(str, Enum):
    READ = "Read"
    WRITE = "Write"
    FETCH = "Fetch"


class HookHandle:
    def __init__(self, emulator: Any):
        self._emulator = emulator
        self._unhook: Any = None
        self._references: tuple[Any, ...] = ()
        self._closed = False

    @property
    def active(self) -> bool:
        return not self._closed

    @property
    def java(self) -> Any:
        return self._unhook

    def _attach(self, unhook: Any) -> None:
        self._unhook = unhook

    def _keep(self, *references: Any) -> HookHandle:
        self._references = references
        return self

    def close(self) -> None:
        if not self._closed:
            if self._unhook is not None:
                self._unhook.unhook()
            self._closed = True

    remove = close

    def __enter__(self) -> HookHandle:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class PermanentRegistration:
    def __init__(self, *references: Any):
        self._references = references

    @property
    def active(self) -> bool:
        return True

    @property
    def removable(self) -> bool:
        return False


class _BackendHookBase:
    def __init__(self, emulator: Any, handle: HookHandle):
        self.emulator = emulator
        self.handle = handle

    def onAttach(self, unhook: Any) -> None:
        self.handle._attach(unhook)

    def detach(self) -> None:
        self.handle.close()

    def _call(self, callback: Callable[..., Any], *args: Any) -> Any:
        try:
            return callback(*args)
        except BaseException as exc:
            self.emulator._capture_callback_error(exc)
            raise


class BackendHooks:
    def __init__(self, emulator: Any):
        self._emulator = emulator

    @staticmethod
    def _range(begin: int | None, end: int | None) -> tuple[int, int]:
        return int(begin or 0), int(end if end is not None else 0x7FFFFFFFFFFFFFFF)

    def code(
        self,
        callback: Callable[[Any, int, int, Any], None],
        *,
        begin: int | None = None,
        end: int | None = None,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(self, backend: Any, address: int, size: int, raw_user_data: Any) -> None:
                self._call(callback, owner._emulator, int(address), int(size), user_data)

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.arm.backend.CodeHook"), inst=impl)
        first, last = self._range(begin, end)
        self._emulator.backend.hook_add_new(proxy, first, last, None)
        return handle._keep(impl, proxy, callback, user_data)

    def block(
        self,
        callback: Callable[[Any, int, int, Any], None],
        *,
        begin: int | None = None,
        end: int | None = None,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hookBlock(self, backend: Any, address: int, size: int, raw_user_data: Any) -> None:
                self._call(callback, owner._emulator, int(address), int(size), user_data)

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.arm.backend.BlockHook"), inst=impl)
        first, last = self._range(begin, end)
        self._emulator.backend.hook_add_new(proxy, first, last, None)
        return handle._keep(impl, proxy, callback, user_data)

    def read(
        self,
        callback: Callable[[Any, int, int, Any], None],
        *,
        begin: int | None = None,
        end: int | None = None,
        user_data: Any = None,
    ) -> HookHandle:
        return self._memory_range("ReadHook", callback, begin, end, user_data)

    def write(
        self,
        callback: Callable[[Any, int, int, int, Any], None],
        *,
        begin: int | None = None,
        end: int | None = None,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(
                self, backend: Any, address: int, size: int, value: int, raw_user_data: Any
            ) -> None:
                self._call(
                    callback,
                    owner._emulator,
                    int(address),
                    int(size),
                    int(value),
                    user_data,
                )

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.arm.backend.WriteHook"), inst=impl)
        first, last = self._range(begin, end)
        self._emulator.backend.hook_add_new(proxy, first, last, None)
        return handle._keep(impl, proxy, callback, user_data)

    def _memory_range(
        self,
        interface: str,
        callback: Callable[[Any, int, int, Any], None],
        begin: int | None,
        end: int | None,
        user_data: Any,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(self, backend: Any, address: int, size: int, raw_user_data: Any) -> None:
                self._call(callback, owner._emulator, int(address), int(size), user_data)

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(
            self._emulator._class(f"com.github.unidbg.arm.backend.{interface}"), inst=impl
        )
        first, last = self._range(begin, end)
        self._emulator.backend.hook_add_new(proxy, first, last, None)
        return handle._keep(impl, proxy, callback, user_data)

    def invalid_memory(
        self,
        events: MemoryHookMask,
        callback: Callable[[Any, int, int, int, MemoryEvent, Any], bool],
        *,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(
                self,
                backend: Any,
                address: int,
                size: int,
                value: int,
                raw_user_data: Any,
                event: Any,
            ) -> bool:
                return bool(
                    self._call(
                        callback,
                        owner._emulator,
                        int(address),
                        int(size),
                        int(value),
                        MemoryEvent(str(event.name())),
                        user_data,
                    )
                )

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.arm.backend.EventMemHook"), inst=impl)
        self._emulator.backend.hook_add_new(proxy, int(events), None)
        return handle._keep(impl, proxy, callback, user_data)

    def interrupt(
        self,
        callback: Callable[[Any, int, int, Any], None],
        *,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(self, backend: Any, intno: int, svc: int, raw_user_data: Any) -> None:
                self._call(callback, owner._emulator, int(intno), int(svc), user_data)

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(
            self._emulator._class("com.github.unidbg.arm.backend.InterruptHook"), inst=impl
        )
        self._emulator.backend.hook_add_new(proxy, None)
        return handle._keep(impl, proxy, callback, user_data)

    def debug(
        self,
        on_code: Callable[[Any, int, int, Any], None],
        on_break: Callable[[Any, int, int, Any], None],
        *,
        begin: int | None = None,
        end: int | None = None,
        user_data: Any = None,
    ) -> HookHandle:
        handle = HookHandle(self._emulator)
        owner = self

        class Callback(_BackendHookBase):
            def hook(self, backend: Any, address: int, size: int, raw_user_data: Any) -> None:
                self._call(on_code, owner._emulator, int(address), int(size), user_data)

            def onBreak(self, backend: Any, address: int, size: int, raw_user_data: Any) -> None:
                self._call(on_break, owner._emulator, int(address), int(size), user_data)

        impl = Callback(self._emulator, handle)
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.arm.backend.DebugHook"), inst=impl)
        first, last = self._range(begin, end)
        self._emulator.backend.debugger_add(proxy, first, last, None)
        return handle._keep(impl, proxy, on_code, on_break, user_data)


class ListenerRegistry:
    def __init__(self, emulator: Any):
        self._emulator = emulator

    def module_loaded(self, callback: Callable[[Any, Any], None]) -> PermanentRegistration:
        owner = self

        class Listener:
            def onLoaded(self, raw_emulator: Any, raw_module: Any) -> None:
                try:
                    from .emulator import Module

                    callback(owner._emulator, Module(owner._emulator, None, raw_module))
                except BaseException as exc:
                    owner._emulator._capture_callback_error(exc)
                    raise

        impl = Listener()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.ModuleListener"), inst=impl)
        self._emulator.memory.java.addModuleListener(proxy)
        registration = PermanentRegistration(impl, proxy, callback)
        self._emulator._callback_refs.append(registration)
        return registration

    def import_symbol(
        self,
        callback: Callable[[Any, str, str, int], int | None],
    ) -> PermanentRegistration:
        owner = self

        class Listener:
            def hook(
                self, svc_memory: Any, library_name: str, symbol_name: str, old_address: int
            ) -> int:
                try:
                    result = callback(
                        owner._emulator,
                        str(library_name),
                        str(symbol_name),
                        int(old_address),
                    )
                    return 0 if result is None else int(result)
                except BaseException as exc:
                    owner._emulator._capture_callback_error(exc)
                    raise

        impl = Listener()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.hook.HookListener"), inst=impl)
        self._emulator.memory.java.addHookListener(proxy)
        registration = PermanentRegistration(impl, proxy, callback)
        self._emulator._callback_refs.append(registration)
        return registration


class MMapRegistration:
    def __init__(self, emulator: Any, previous: Any, proxy: Any, references: tuple[Any, ...]):
        self._emulator = emulator
        self._previous = previous
        self.java = proxy
        self._references = references
        self._closed = False

    @property
    def active(self) -> bool:
        return not self._closed

    def close(self) -> None:
        if not self._closed:
            if self._emulator.memory.java.getMMapListener() == self.java:
                self._emulator.memory.java.setMMapListener(self._previous)
            self._closed = True

    def __enter__(self) -> MMapRegistration:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def install_mmap_listener(
    emulator: Any,
    on_map: Callable[[int, int, int], None] | None,
    on_protect: Callable[[int, int, int], int | None] | None,
    on_unmap: Callable[[int, int], None] | None,
) -> MMapRegistration:
    previous = emulator.memory.java.getMMapListener()

    class Listener:
        def onMap(self, address: int, size: int, protection: int) -> None:
            try:
                if previous is not None:
                    previous.onMap(address, size, protection)
                if on_map is not None:
                    on_map(int(address), int(size), int(protection))
            except BaseException as exc:
                emulator._capture_callback_error(exc)
                raise

        def onProtect(self, address: int, size: int, protection: int) -> int:
            try:
                effective = (
                    int(previous.onProtect(address, size, protection))
                    if previous is not None
                    else int(protection)
                )
                if on_protect is not None:
                    result = on_protect(int(address), int(size), effective)
                    if result is not None:
                        effective = int(result)
                return effective
            except BaseException as exc:
                emulator._capture_callback_error(exc)
                raise

        def onUnmap(self, address: int, size: int) -> None:
            try:
                if previous is not None:
                    previous.onUnmap(address, size)
                if on_unmap is not None:
                    on_unmap(int(address), int(size))
            except BaseException as exc:
                emulator._capture_callback_error(exc)
                raise

    impl = Listener()
    proxy = jpype.JProxy(emulator._class("com.github.unidbg.memory.MMapListener"), inst=impl)
    registration = MMapRegistration(
        emulator, previous, proxy, (impl, proxy, on_map, on_protect, on_unmap)
    )
    emulator.memory.java.setMMapListener(proxy)
    emulator._callback_refs.append(registration)
    return registration


@dataclass(frozen=True, slots=True)
class LeakRecord:
    address: int
    size: int
    permissions: int
    guest_backtrace: tuple[str, ...]
    host_backtrace: tuple[str, ...]
    timestamp: int
    java: Any


class MemoryLeakTracker:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java
        self._closed = False

    @property
    def leaks(self) -> tuple[LeakRecord, ...]:
        return tuple(
            LeakRecord(
                address=int(item.address),
                size=int(item.size),
                permissions=int(item.perms),
                guest_backtrace=tuple(str(line) for line in item.guestBacktrace),
                host_backtrace=tuple(str(line) for line in item.hostStackTrace),
                timestamp=int(item.timestamp),
                java=item,
            )
            for item in self.java.getLeaks()
        )

    @property
    def total_allocations(self) -> int:
        return int(self.java.getTotalAllocations())

    @property
    def total_deallocations(self) -> int:
        return int(self.java.getTotalDeallocations())

    @property
    def total_leaked_size(self) -> int:
        return int(self.java.getTotalLeakedSize())

    def print_report(self) -> None:
        self.java.printReport()

    def close(self) -> None:
        if not self._closed:
            self.java.close()
            self._closed = True

    def __enter__(self) -> MemoryLeakTracker:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


@dataclass(frozen=True, slots=True)
class HookDecision:
    call_original: bool
    value: int = 0

    @classmethod
    def original(cls) -> HookDecision:
        return cls(True, 0)

    call_original = original

    @classmethod
    def return_value(cls, value: int) -> HookDecision:
        return cls(False, int(value))


class HookContext:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    def int_arg(self, index: int) -> int:
        return int(self.java.getIntArg(index))

    def long_arg(self, index: int) -> int:
        return int(self.java.getLongArg(index))

    def pointer_arg(self, index: int) -> Pointer | None:
        pointer = self.java.getPointerArg(index)
        return None if pointer is None else Pointer(self._emulator, int(pointer.peer))

    def x(self, index: int) -> int:
        return int(self.java.getXLong(index))

    def set_x(self, index: int, value: int) -> None:
        self.java.setXLong(int(index), jpype.JLong(value))

    @property
    def lr(self) -> int:
        return int(self.java.getLR())

    @property
    def fp(self) -> int:
        return int(self.java.getFp())

    @property
    def stack_pointer(self) -> Pointer:
        return Pointer(self._emulator, int(self.java.getStackPointer().peer))

    def set_stack_pointer(self, pointer: Pointer | int) -> None:
        value = pointer if isinstance(pointer, Pointer) else Pointer(self._emulator, int(pointer))
        self.java.setStackPointer(value.java)


@dataclass(frozen=True, slots=True)
class HookEntry:
    hook_id: int
    address: int
    java: Any


def _target(value: Any) -> Any:
    if hasattr(value, "java"):
        return value.java
    return jpype.JLong(int(value))


class _ReplaceDelegate:
    def __init__(self, emulator: Any, on_call: Callable[..., Any], post_call: Callable[..., Any] | None):
        self.emulator = emulator
        self.on_call = on_call
        self.post_call = post_call
        self.states: dict[int, Any] = {}
        self.next_state_id = 1
        self.result = emulator._class("io.pyunidbg.bridge.HookDecisionResult")

    def onCall(self, raw_emulator: Any, raw_context: Any, origin: int) -> Any:
        try:
            context = HookContext(self.emulator, raw_context)
            returned = self.on_call(self.emulator, context, int(origin))
            state = None
            if isinstance(returned, tuple):
                decision, state = returned
            else:
                decision = returned
            if decision is None:
                decision = HookDecision.original()
            if not isinstance(decision, HookDecision):
                raise TypeError("replace callbacks must return HookDecision, (HookDecision, state), or None")
            state_id = 0
            if self.post_call is not None:
                state_id = self.next_state_id
                self.next_state_id += 1
                self.states[state_id] = state
            return (
                self.result.callOriginal(jpype.JLong(state_id))
                if decision.call_original
                else self.result.returnValue(jpype.JLong(decision.value), jpype.JLong(state_id))
            )
        except BaseException as exc:
            self.emulator._capture_callback_error(exc)
            raise

    def postCall(self, raw_emulator: Any, raw_context: Any, state_id: int) -> None:
        try:
            state = self.states.pop(int(state_id), None)
            if self.post_call is not None:
                self.post_call(self.emulator, HookContext(self.emulator, raw_context), state)
        except BaseException as exc:
            self.emulator._capture_callback_error(exc)
            raise


def make_replace_callback(
    emulator: Any,
    on_call: Callable[..., Any],
    post_call: Callable[..., Any] | None,
) -> tuple[Any, tuple[Any, ...]]:
    impl = _ReplaceDelegate(emulator, on_call, post_call)
    proxy = jpype.JProxy(emulator._class("io.pyunidbg.bridge.ReplaceDelegate"), inst=impl)
    bridge = emulator._class("io.pyunidbg.bridge.BridgeReplaceCallback")(proxy)
    return bridge, (impl, proxy, bridge, on_call, post_call)


class HookZzEngine:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    def replace(
        self,
        target: Any,
        on_call: Callable[..., Any],
        *,
        post_call: Callable[..., Any] | None = None,
    ) -> PermanentRegistration:
        bridge, references = make_replace_callback(self._emulator, on_call, post_call)
        self.java.replace(_target(target), bridge, post_call is not None)
        registration = PermanentRegistration(*references)
        self._emulator._callback_refs.append(registration)
        return registration

    def replace_svc(self, target: Any, service: SvcRegistration) -> PermanentRegistration:
        self.java.replace(_target(target), service.java)
        registration = PermanentRegistration(service)
        self._emulator._callback_refs.append(registration)
        return registration

    def wrap(
        self,
        target: Any,
        before: Callable[[Any, HookContext, HookEntry], Any],
        *,
        after: Callable[[Any, HookContext, HookEntry, Any], None] | None = None,
    ) -> PermanentRegistration:
        emulator = self._emulator
        states: dict[int, Any] = {}
        next_state_id = [1]

        class Delegate:
            def preCall(self, raw_emulator: Any, raw_context: Any, raw_info: Any) -> int:
                try:
                    info = HookEntry(int(raw_info.getHookId()), int(raw_info.getAddress()), raw_info)
                    state_id = next_state_id[0]
                    next_state_id[0] += 1
                    states[state_id] = before(emulator, HookContext(emulator, raw_context), info)
                    return state_id
                except BaseException as exc:
                    emulator._capture_callback_error(exc)
                    raise

            def postCall(
                self, raw_emulator: Any, raw_context: Any, raw_info: Any, state_id: int
            ) -> None:
                try:
                    state = states.pop(int(state_id), None)
                    if after is not None:
                        info = HookEntry(int(raw_info.getHookId()), int(raw_info.getAddress()), raw_info)
                        after(emulator, HookContext(emulator, raw_context), info, state)
                except BaseException as exc:
                    emulator._capture_callback_error(exc)
                    raise

        impl = Delegate()
        proxy = jpype.JProxy(emulator._class("io.pyunidbg.bridge.WrapDelegate"), inst=impl)
        bridge = emulator._class("io.pyunidbg.bridge.BridgeWrapCallback")(proxy)
        self.java.wrap(_target(target), bridge)
        registration = PermanentRegistration(impl, proxy, bridge, before, after, states)
        emulator._callback_refs.append(registration)
        return registration

    def instrument(
        self,
        target: Any,
        callback: Callable[[Any, HookContext, HookEntry], None],
    ) -> PermanentRegistration:
        emulator = self._emulator

        class Delegate:
            def onInstrument(self, raw_emulator: Any, raw_context: Any, raw_info: Any) -> None:
                try:
                    info = HookEntry(int(raw_info.getHookId()), int(raw_info.getAddress()), raw_info)
                    callback(emulator, HookContext(emulator, raw_context), info)
                except BaseException as exc:
                    emulator._capture_callback_error(exc)
                    raise

        impl = Delegate()
        proxy = jpype.JProxy(emulator._class("io.pyunidbg.bridge.InstrumentDelegate"), inst=impl)
        bridge = emulator._class("io.pyunidbg.bridge.BridgeInstrumentCallback")(proxy)
        self.java.instrument(_target(target), bridge)
        registration = PermanentRegistration(impl, proxy, bridge, callback)
        emulator._callback_refs.append(registration)
        return registration

    def enable_branch_mode(self, enabled: bool = True) -> None:
        if enabled:
            self.java.enable_arm_arm64_b_branch()
        else:
            self.java.disable_arm_arm64_b_branch()

    def log_to(self, path: str | Path) -> None:
        self.java.switch_to_file_log(str(Path(path)))


class XHookEngine:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    def register(
        self,
        library: str,
        symbol: str,
        on_call: Callable[..., Any],
        *,
        post_call: Callable[..., Any] | None = None,
    ) -> PermanentRegistration:
        bridge, references = make_replace_callback(self._emulator, on_call, post_call)
        self.java.register(library, symbol, bridge, post_call is not None)
        registration = PermanentRegistration(*references)
        self._emulator._callback_refs.append(registration)
        return registration

    def refresh(self) -> None:
        self.java.refresh()


class WhaleEngine:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    def replace(
        self,
        target: Any,
        on_call: Callable[..., Any],
        *,
        post_call: Callable[..., Any] | None = None,
    ) -> PermanentRegistration:
        bridge, references = make_replace_callback(self._emulator, on_call, post_call)
        self.java.inlineHookFunction(_target(target), bridge, post_call is not None)
        registration = PermanentRegistration(*references)
        self._emulator._callback_refs.append(registration)
        return registration

    def import_symbol(
        self,
        symbol: str,
        on_call: Callable[..., Any],
        *,
        post_call: Callable[..., Any] | None = None,
    ) -> PermanentRegistration:
        bridge, references = make_replace_callback(self._emulator, on_call, post_call)
        self.java.importHookFunction(symbol, bridge, post_call is not None)
        registration = PermanentRegistration(*references)
        self._emulator._callback_refs.append(registration)
        return registration

    def replace_svc(self, target: Any, service: SvcRegistration) -> PermanentRegistration:
        self.java.replace(_target(target), service.java)
        registration = PermanentRegistration(service)
        self._emulator._callback_refs.append(registration)
        return registration


class InlineHooks:
    def __init__(self, emulator: Any):
        self._emulator = emulator
        self._instances: dict[str, Any] = {}

    def _hookzz(self, name: str, class_name: str) -> HookZzEngine:
        if name not in self._instances:
            raw = self._emulator._class(class_name).getInstance(self._emulator.java)
            self._instances[name] = HookZzEngine(self._emulator, raw)
        return self._instances[name]

    @property
    def dobby(self) -> HookZzEngine:
        return self._hookzz("dobby", "com.github.unidbg.hook.hookzz.Dobby")

    @property
    def hookzz(self) -> HookZzEngine:
        return self._hookzz("hookzz", "com.github.unidbg.hook.hookzz.HookZz")

    @property
    def xhook(self) -> XHookEngine:
        if "xhook" not in self._instances:
            raw = self._emulator._class("com.github.unidbg.linux.android.XHookImpl").getInstance(
                self._emulator.java
            )
            self._instances["xhook"] = XHookEngine(self._emulator, raw)
        return self._instances["xhook"]

    @property
    def whale(self) -> WhaleEngine:
        if "whale" not in self._instances:
            raw = self._emulator._class("com.github.unidbg.hook.whale.Whale").getInstance(
                self._emulator.java
            )
            self._instances["whale"] = WhaleEngine(self._emulator, raw)
        return self._instances["whale"]


class SvcRegistration:
    def __init__(self, emulator: Any, pointer: Pointer, java: Any, references: tuple[Any, ...]):
        self._emulator = emulator
        self.pointer = pointer
        self.java = java
        self._references = references

    def call(self, *args: Any) -> Any:
        return self._emulator.call_address(int(self.pointer), *args)


def register_svc(
    emulator: Any,
    callback: Callable[[Any], int],
    *,
    name: str = "pyunidbg",
    before: Callable[[Any], None] | None = None,
    after: Callable[[Any], None] | None = None,
) -> SvcRegistration:
    class Delegate:
        def handle(self, raw_emulator: Any) -> int:
            try:
                return int(callback(emulator))
            except BaseException as exc:
                emulator._capture_callback_error(exc)
                raise

        def handlePreCallback(self, raw_emulator: Any) -> None:
            if before is not None:
                try:
                    before(emulator)
                except BaseException as exc:
                    emulator._capture_callback_error(exc)
                    raise

        def handlePostCallback(self, raw_emulator: Any) -> None:
            if after is not None:
                try:
                    after(emulator)
                except BaseException as exc:
                    emulator._capture_callback_error(exc)
                    raise

    impl = Delegate()
    proxy = jpype.JProxy(emulator._class("io.pyunidbg.bridge.SvcDelegate"), inst=impl)
    bridge = emulator._class("io.pyunidbg.bridge.BridgeArm64Svc")(name, proxy)
    raw_pointer = emulator.java.getSvcMemory().registerSvc(bridge)
    registration = SvcRegistration(
        emulator,
        Pointer(emulator, int(raw_pointer.peer)),
        bridge,
        (impl, proxy, bridge, callback, before, after),
    )
    emulator._callback_refs.append(registration)
    return registration


def install_system_property_provider(
    emulator: Any, callback: Callable[[str], str | None]
) -> PermanentRegistration:
    def get_property(key: str) -> str | None:
        try:
            return callback(str(key))
        except BaseException as exc:
            emulator._capture_callback_error(exc)
            raise

    methods = {
        "getProperty": get_property,
        "__system_property_find": lambda key: None,
    }
    proxy = jpype.JProxy(
        emulator._class("com.github.unidbg.linux.android.SystemPropertyProvider"), dict=methods
    )
    hook = emulator._class("com.github.unidbg.linux.android.SystemPropertyHook")(emulator.java)
    hook.setPropertyProvider(proxy)
    emulator.memory.java.addHookListener(hook)
    registration = PermanentRegistration(methods, proxy, hook, callback)
    emulator._callback_refs.append(registration)
    return registration
