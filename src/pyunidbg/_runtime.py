from __future__ import annotations

import ctypes
import platform
import re
import shutil
import subprocess
import threading
from pathlib import Path
from typing import Any

import jpype

from .errors import JavaRuntimeError, JvmAlreadyRunningError, UnsupportedPlatformError

_LOCK = threading.RLock()
_STARTED_BY_US = False
_PACKAGE_DIR = Path(__file__).resolve().parent
_VENDOR_DIR = _PACKAGE_DIR / "_vendor"
_JAR_DIR = _VENDOR_DIR / "jars"
_NATIVE_DIR = _VENDOR_DIR / "native"
_REQUIRED_CLASS = "io.pyunidbg.bridge.BridgeJni"


def _validate_platform() -> None:
    machine = platform.machine().lower()
    if platform.system() != "Linux" or machine not in {"x86_64", "amd64"}:
        raise UnsupportedPlatformError(
            f"pyunidbg 0.1 supports Linux x86_64 only; found {platform.system()} {machine}"
        )


def _find_java() -> tuple[Path, int]:
    executable = shutil.which("java")
    if executable is None:
        raise JavaRuntimeError("Java 17+ is required, but 'java' is not on PATH")
    try:
        result = subprocess.run(
            [executable, "-version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
        )
    except OSError as exc:
        raise JavaRuntimeError(f"failed to execute {executable}: {exc}") from exc
    output = result.stderr + result.stdout
    match = re.search(r'version\s+"(?P<version>\d+)(?:\.(\d+))?', output)
    if result.returncode != 0 or match is None:
        raise JavaRuntimeError(f"could not determine Java version from {executable}: {output.strip()}")
    major = int(match.group("version"))
    if major < 17:
        raise JavaRuntimeError(f"Java 17+ is required; {executable} reports Java {major}")
    return Path(executable).resolve(), major


def _jvm_library(java: Path) -> Path:
    candidates = (
        java.parent.parent / "lib" / "server" / "libjvm.so",
        java.parent.parent / "jre" / "lib" / "amd64" / "server" / "libjvm.so",
    )
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    try:
        return Path(jpype.getDefaultJVMPath())
    except jpype.JVMNotFoundException as exc:
        raise JavaRuntimeError(f"could not locate libjvm.so for {java}") from exc


def _classpath() -> list[str]:
    jars = sorted(_JAR_DIR.glob("*.jar"))
    if not jars or not any(path.name == "pyunidbg-bridge.jar" for path in jars):
        raise JavaRuntimeError(f"packaged Java artifacts are missing from {_JAR_DIR}")
    return [str(path) for path in jars]


def _preload_native_dependencies() -> None:
    # The JNI bridge libraries have dependencies with no rpath. Loading their
    # direct native dependencies globally makes System.loadLibrary deterministic.
    for name in ("libunicorn.so", "libcapstone.so", "libkeystone.so", "libdisassembler.so"):
        path = _NATIVE_DIR / name
        if not path.is_file():
            raise JavaRuntimeError(f"packaged native library is missing: {path}")
        try:
            ctypes.CDLL(str(path), mode=ctypes.RTLD_GLOBAL)
        except OSError as exc:
            raise JavaRuntimeError(f"failed to load packaged native library {path}: {exc}") from exc


def ensure_jvm() -> None:
    """Start the bundled unidbg JVM classpath once, on demand."""
    global _STARTED_BY_US
    with _LOCK:
        if jpype.isJVMStarted():
            try:
                jpype.JClass(_REQUIRED_CLASS)
            except (TypeError, jpype.JException) as exc:
                raise JvmAlreadyRunningError(
                    "a JVM is already running without the pyunidbg classpath; "
                    "import and initialize pyunidbg before other JPype users"
                ) from exc
            return

        _validate_platform()
        java, _ = _find_java()
        _preload_native_dependencies()
        jpype.startJVM(
            str(_jvm_library(java)),
            f"-Djava.library.path={_NATIVE_DIR}",
            "-Dfile.encoding=UTF-8",
            classpath=_classpath(),
            convertStrings=True,
        )
        _STARTED_BY_US = True
        try:
            jpype.JClass(_REQUIRED_CLASS)
        except (TypeError, jpype.JException) as exc:
            raise JavaRuntimeError("the packaged pyunidbg Java bridge could not be loaded") from exc


def java_class(name: str) -> Any:
    """Return a Java class from the pyunidbg JVM."""
    ensure_jvm()
    return jpype.JClass(name)
