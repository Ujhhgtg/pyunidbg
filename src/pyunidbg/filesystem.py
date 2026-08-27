from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import jpype


@dataclass(frozen=True, slots=True)
class IOFailure:
    errno: int


@dataclass(frozen=True, slots=True)
class IOFallback:
    value: bytes | str | Path | Any


class FileSystem:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    @property
    def root_dir(self) -> Path:
        return Path(str(self.java.getRootDir().getAbsolutePath()))

    def create_work_dir(self) -> Path:
        return Path(str(self.java.createWorkDir().getAbsolutePath()))

    def open(self, path: str, flags: int = 0) -> Any:
        return self.java.open(path, int(flags))

    def unlink(self, path: str) -> None:
        self.java.unlink(path)

    def mkdir(self, path: str, mode: int = 0o755) -> bool:
        return bool(self.java.mkdir(path, int(mode)))

    def rmdir(self, path: str) -> None:
        self.java.rmdir(path)

    def rename(self, old_path: str, new_path: str) -> int:
        return int(self.java.rename(old_path, new_path))

    def create_simple_file_io(self, host_path: str | Path, flags: int, guest_path: str) -> Any:
        file_class = self._emulator._class("java.io.File")
        return self.java.createSimpleFileIO(file_class(str(Path(host_path))), int(flags), guest_path)

    def create_directory_file_io(self, host_path: str | Path, flags: int, guest_path: str) -> Any:
        file_class = self._emulator._class("java.io.File")
        return self.java.createDirectoryFileIO(file_class(str(Path(host_path))), int(flags), guest_path)


class SyscallHandler:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    @property
    def verbose(self) -> bool:
        return bool(self.java.isVerbose())

    @verbose.setter
    def verbose(self, value: bool) -> None:
        self.java.setVerbose(bool(value))

    def enable_thread_dispatcher(self, enabled: bool = True) -> None:
        self.java.setEnableThreadDispatcher(bool(enabled))

    def open(self, path: str, flags: int = 0) -> int:
        return int(self.java.open(self._emulator.java, path, int(flags)))

    def file_io(self, descriptor: int) -> Any:
        return self.java.getFileIO(int(descriptor))

    def close(self, descriptor: int) -> None:
        self.java.closeFileIO(int(descriptor))

    def add_file_io(self, file_io: Any) -> int:
        return int(self.java.addFileIO(file_io.java if hasattr(file_io, "java") else file_io))

    def create_signal_handler_task(self, signal: int) -> Any:
        return self.java.createSignalHandlerTask(self._emulator.java, int(signal))

    def set_breaker(self, breaker: Any) -> None:
        self.java.setBreaker(breaker.java if hasattr(breaker, "java") else breaker)

    def destroy(self) -> None:
        self.java.destroy()

    def set_file_listener(
        self,
        *,
        on_open: Callable[[Any, str, Any], None] | None = None,
        on_read: Callable[[Any, str, bytes], None] | None = None,
        on_write: Callable[[Any, str, bytes], None] | None = None,
        on_close: Callable[[Any, Any], None] | None = None,
    ) -> None:
        owner = self

        class Listener:
            def onOpenSuccess(self, raw_emulator: Any, path: str, file_io: Any) -> None:
                if on_open is not None:
                    on_open(owner._emulator, str(path), file_io)

            def onRead(self, raw_emulator: Any, path: str, data: Any) -> None:
                if on_read is not None:
                    on_read(owner._emulator, str(path), bytes(data))

            def onWrite(self, raw_emulator: Any, path: str, data: Any) -> None:
                if on_write is not None:
                    on_write(owner._emulator, str(path), bytes(data))

            def onClose(self, raw_emulator: Any, file_io: Any) -> None:
                if on_close is not None:
                    on_close(owner._emulator, file_io)

        impl = Listener()
        proxy = jpype.JProxy(self._emulator._class("com.github.unidbg.unix.FileListener"), inst=impl)
        self.java.setFileListener(proxy)
        self._emulator._callback_refs.extend((impl, proxy, on_open, on_read, on_write, on_close))

    def clear_file_listener(self) -> None:
        self.java.setFileListener(None)


def install_io_resolver(emulator: Any, callback: Callable[[Any, str, int], Any]) -> Any:
    file_result = emulator._class("com.github.unidbg.file.FileResult")
    byte_io = emulator._class("com.github.unidbg.linux.file.ByteArrayFileIO")
    simple_io = emulator._class("com.github.unidbg.linux.file.SimpleFileIO")
    file_class = emulator._class("java.io.File")

    def make_io(value: Any, path: str, flags: int) -> Any:
        value = value.java if hasattr(value, "java") else value
        if isinstance(value, (bytes, bytearray, memoryview)):
            factory: Any = jpype.JArray(jpype.JByte)
            data = factory(bytes(value))
            return byte_io(int(flags), path, data)
        if isinstance(value, (str, Path)):
            return simple_io(int(flags), file_class(str(Path(value))), path)
        return value

    class Resolver:
        def resolve(self, raw_emulator: Any, path: str, flags: int) -> Any:
            result = callback(emulator, str(path), int(flags))
            if result is None:
                return None
            if isinstance(result, IOFailure):
                return file_result.failed(int(result.errno))
            if isinstance(result, IOFallback):
                return file_result.fallback(make_io(result.value, str(path), int(flags)))
            return file_result.success(make_io(result, str(path), int(flags)))

    impl = Resolver()
    proxy = jpype.JProxy(emulator._class("com.github.unidbg.file.IOResolver"), inst=impl)
    emulator.java.getSyscallHandler().addIOResolver(proxy)
    emulator._callback_refs.extend((impl, proxy, callback))
    return proxy
