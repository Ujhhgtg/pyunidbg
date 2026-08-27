"""Python bindings for unidbg's Android ARM64 emulator."""

from ._runtime import ensure_jvm, java_class
from .debug import Breakpoint, Debugger, Trace
from .dvm import VM, DvmClass, DvmObject, VaList
from .emulator import AndroidEmulator, MemoryRegion, Module, RegisterContext, Symbol
from .errors import (
    JavaRuntimeError,
    JvmAlreadyRunningError,
    PyUnidbgError,
    UnsupportedPlatformError,
)
from .filesystem import FileSystem, IOFailure, IOFallback, SyscallHandler
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
from .jni import NOT_HANDLED, JniHandler
from .mcp import EmulatorController, McpEvent, PyUnidbgMcpServer
from .memory import Allocation, Memory, Pointer

__all__ = [
    "NOT_HANDLED",
    "VM",
    "Allocation",
    "AndroidEmulator",
    "Breakpoint",
    "Debugger",
    "DvmClass",
    "DvmObject",
    "EmulatorController",
    "FileSystem",
    "HookContext",
    "HookDecision",
    "HookEntry",
    "HookHandle",
    "IOFailure",
    "IOFallback",
    "JavaRuntimeError",
    "JniHandler",
    "JvmAlreadyRunningError",
    "LeakRecord",
    "McpEvent",
    "Memory",
    "MemoryEvent",
    "MemoryHookMask",
    "MemoryLeakTracker",
    "MemoryRegion",
    "Module",
    "PermanentRegistration",
    "Pointer",
    "PyUnidbgError",
    "PyUnidbgMcpServer",
    "RegisterContext",
    "SvcRegistration",
    "Symbol",
    "SyscallHandler",
    "Trace",
    "UnsupportedPlatformError",
    "VaList",
    "ensure_jvm",
    "java_class",
]

__version__ = "0.1.0"
