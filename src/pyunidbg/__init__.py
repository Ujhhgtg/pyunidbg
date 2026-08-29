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
from .pool import (
    BorrowTimeoutError,
    EmulatorWorker,
    PoolClosedError,
    PoolStats,
    WorkerLease,
    WorkerPool,
)
from .serialization import InspectionReport, MemoryCapture
from .threads import GuestTask, GuestTaskInfo, GuestThreadDispatcher, SignalSet

__all__ = [
    "NOT_HANDLED",
    "VM",
    "Allocation",
    "AndroidEmulator",
    "BorrowTimeoutError",
    "Breakpoint",
    "Debugger",
    "DvmClass",
    "DvmObject",
    "EmulatorController",
    "EmulatorWorker",
    "FileSystem",
    "GuestTask",
    "GuestTaskInfo",
    "GuestThreadDispatcher",
    "HookContext",
    "HookDecision",
    "HookEntry",
    "HookHandle",
    "IOFailure",
    "IOFallback",
    "InspectionReport",
    "JavaRuntimeError",
    "JniHandler",
    "JvmAlreadyRunningError",
    "LeakRecord",
    "McpEvent",
    "Memory",
    "MemoryCapture",
    "MemoryEvent",
    "MemoryHookMask",
    "MemoryLeakTracker",
    "MemoryRegion",
    "Module",
    "PermanentRegistration",
    "Pointer",
    "PoolClosedError",
    "PoolStats",
    "PyUnidbgError",
    "PyUnidbgMcpServer",
    "RegisterContext",
    "SignalSet",
    "SvcRegistration",
    "Symbol",
    "SyscallHandler",
    "Trace",
    "UnsupportedPlatformError",
    "VaList",
    "WorkerLease",
    "WorkerPool",
    "ensure_jvm",
    "java_class",
]

__version__ = "0.1.0"
