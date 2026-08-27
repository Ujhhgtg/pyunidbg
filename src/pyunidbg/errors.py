class PyUnidbgError(RuntimeError):
    """Base class for pyunidbg setup errors."""


class UnsupportedPlatformError(PyUnidbgError):
    """Raised when pyunidbg is used outside Linux x86_64."""


class JavaRuntimeError(PyUnidbgError):
    """Raised when a suitable Java runtime cannot be found."""


class JvmAlreadyRunningError(PyUnidbgError):
    """Raised when an incompatible JVM was started before pyunidbg."""
