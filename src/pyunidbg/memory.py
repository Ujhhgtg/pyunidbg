from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jpype


class Pointer:
    def __init__(self, emulator: Any, address: int):
        self._emulator = emulator
        self.address = int(address)

    @property
    def java(self) -> Any:
        pointer_class = self._emulator._class("com.github.unidbg.pointer.UnidbgPointer")
        return pointer_class.pointer(self._emulator.java, jpype.JLong(self.address))

    def offset(self, amount: int) -> Pointer:
        return Pointer(self._emulator, self.address + amount)

    def read(self, size: int, offset: int = 0) -> bytes:
        return self._emulator.memory.read(self.address + offset, size)

    def write(self, data: bytes | bytearray | memoryview, offset: int = 0) -> None:
        self._emulator.memory.write(self.address + offset, data)

    def read_u8(self, offset: int = 0) -> int:
        return int.from_bytes(self.read(1, offset), "little")

    def read_u32(self, offset: int = 0, *, signed: bool = False) -> int:
        return int.from_bytes(self.read(4, offset), "little", signed=signed)

    def read_u64(self, offset: int = 0, *, signed: bool = False) -> int:
        return int.from_bytes(self.read(8, offset), "little", signed=signed)

    def write_u8(self, offset: int, value: int) -> None:
        self.write(int(value).to_bytes(1, "little", signed=False), offset)

    def write_u32(self, offset: int, value: int, *, signed: bool = False) -> None:
        self.write(int(value).to_bytes(4, "little", signed=signed), offset)

    def write_u64(self, offset: int, value: int, *, signed: bool = False) -> None:
        self.write(int(value).to_bytes(8, "little", signed=signed), offset)

    def __int__(self) -> int:
        return self.address

    def __repr__(self) -> str:
        return f"Pointer(0x{self.address:x})"


@dataclass(slots=True)
class Allocation:
    _emulator: Any
    java: Any

    @property
    def pointer(self) -> Pointer:
        return Pointer(self._emulator, int(self.java.getPointer().peer))

    def free(self) -> None:
        self.java.free()


class Memory:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    def malloc(self, size: int, *, heap: bool = True) -> Allocation:
        return Allocation(self._emulator, self.java.malloc(int(size), bool(heap)))

    def pointer(self, address: int) -> Pointer:
        return Pointer(self._emulator, address)

    def read(self, address: int, size: int) -> bytes:
        return bytes(self._emulator.backend.mem_read(int(address), int(size)))

    def write(self, address: int, data: bytes | bytearray | memoryview) -> None:
        self._emulator.backend.mem_write(int(address), bytes(data))

    def mmap(self, size: int, protection: int) -> Pointer:
        raw = self._emulator._run_checked(lambda: self.java.mmap(int(size), int(protection)))
        return Pointer(self._emulator, int(raw.peer))

    def mprotect(self, address: int, size: int, protection: int) -> int:
        return int(
            self._emulator._run_checked(
                lambda: self.java.mprotect(int(address), int(size), int(protection))
            )
        )

    def munmap(self, address: int, size: int) -> int:
        return int(
            self._emulator._run_checked(lambda: self.java.munmap(int(address), int(size)))
        )

    def listen_mmap(
        self,
        *,
        on_map: Any = None,
        on_protect: Any = None,
        on_unmap: Any = None,
    ) -> Any:
        from .hooks import install_mmap_listener

        return install_mmap_listener(self._emulator, on_map, on_protect, on_unmap)
