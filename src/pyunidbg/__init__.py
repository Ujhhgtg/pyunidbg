"""Python bindings for unidbg's Android ARM64 emulator."""

from ._runtime import ensure_jvm, java_class
from .dvm import DvmClass, DvmObject, VM, VaList
from .debug import Breakpoint, Debugger, Trace
from .emulator import AndroidEmulator, MemoryRegion, Module, RegisterContext, Symbol
from .errors import (
    JavaRuntimeError,
    JvmAlreadyRunningError,
    PyUnidbgError,
    UnsupportedPlatformError,
)
from .jni import NOT_HANDLED, JniHandler
from .filesystem import FileSystem, IOFailure, IOFallback, SyscallHandler
from .memory import Allocation, Memory, Pointer
from .hooks import (
    HookContext,
    HookDecision,
    HookEntry,
    HookHandle,
    LeakRecord,
    MemoryEvent,
    MemoryHookMask,
    MemoryLeakTracker,
    PermanentRegistration,
    SvcRegistration,
)

__all__ = [
    "Allocation",
    "AndroidEmulator",
    "Breakpoint",
    "Debugger",
    "DvmClass",
    "DvmObject",
    "FileSystem",
    "IOFailure",
    "IOFallback",
    "HookContext",
    "HookDecision",
    "HookEntry",
    "HookHandle",
    "JavaRuntimeError",
    "JniHandler",
    "JvmAlreadyRunningError",
    "LeakRecord",
    "Memory",
    "MemoryEvent",
    "MemoryHookMask",
    "MemoryLeakTracker",
    "MemoryRegion",
    "Module",
    "NOT_HANDLED",
    "Pointer",
    "PermanentRegistration",
    "PyUnidbgError",
    "RegisterContext",
    "Symbol",
    "SvcRegistration",
    "SyscallHandler",
    "Trace",
    "UnsupportedPlatformError",
    "VM",
    "VaList",
    "ensure_jvm",
    "java_class",
]

__version__ = "0.1.0"
