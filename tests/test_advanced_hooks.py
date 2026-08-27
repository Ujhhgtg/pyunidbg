from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libadd.so"


def test_backend_hooks_removal_invalid_memory_and_interrupts() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.backend-hooks") as emulator:
        module = emulator.load_library(FIXTURE)
        allocation = emulator.memory.malloc(16)
        allocation.pointer.write_u64(0, 5)
        code: list[int] = []
        blocks: list[int] = []
        reads: list[tuple[int, int, str]] = []
        writes: list[tuple[int, int, int, str]] = []

        code_hook = emulator.hooks.code(
            lambda _emulator, address, _size, _data: code.append(address),
            begin=module.base,
            end=module.base + module.size,
        )
        block_hook = emulator.hooks.block(
            lambda _emulator, address, _size, _data: blocks.append(address),
            begin=module.base,
            end=module.base + module.size,
        )
        read_hook = emulator.hooks.read(
            lambda _emulator, address, size, data: reads.append((address, size, data)),
            begin=int(allocation.pointer),
            end=int(allocation.pointer) + 8,
            user_data="read",
        )
        write_hook = emulator.hooks.write(
            lambda _emulator, address, size, value, data: writes.append(
                (address, size, value, data)
            ),
            begin=int(allocation.pointer),
            end=int(allocation.pointer) + 8,
            user_data="write",
        )
        assert int(module.call_symbol("read_number", allocation.pointer)) == 5
        module.call_symbol("write_number", allocation.pointer, 11)
        assert code and blocks
        assert reads[-1] == (int(allocation.pointer), 8, "read")
        assert writes[-1] == (int(allocation.pointer), 8, 11, "write")

        code_count = len(code)
        code_hook.close()
        code_hook.close()
        assert not code_hook.active
        assert int(module.call_symbol("add_numbers", 1, 2)) == 3
        assert len(code) == code_count
        block_hook.close()
        read_hook.close()
        write_hook.close()

        events: list[tuple[int, pyunidbg.MemoryEvent]] = []

        def recover(_emulator, address, size, _value, event, _data):
            events.append((address, event))
            emulator.backend.mem_map(address & ~0xFFF, 0x1000, 3)
            emulator.backend.mem_write(address, (123).to_bytes(size, "little"))
            return True

        invalid = emulator.hooks.invalid_memory(
            pyunidbg.MemoryHookMask.READ_UNMAPPED, recover
        )
        assert int(module.call_symbol("read_number", 0x40000000)) == 123
        assert events == [(0x40000000, pyunidbg.MemoryEvent.READ)]
        invalid.close()

        interrupts: list[tuple[int, int]] = []
        interrupt = emulator.hooks.interrupt(
            lambda _emulator, intno, svc, _data: interrupts.append((intno, svc))
        )
        service = emulator.register_svc(lambda _emulator: 7, name="seven")
        assert int(service.call()) == 7
        assert interrupts
        interrupt.close()


def test_listeners_mmap_leaks_imports_and_system_properties() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.listeners") as emulator:
        replacement = emulator.register_svc(lambda _emulator: 66, name="dep-value")
        loaded: list[str] = []
        imported: list[tuple[str, str, int]] = []
        module_registration = emulator.listeners.module_loaded(
            lambda _emulator, module: loaded.append(module.name)
        )
        import_registration = emulator.listeners.import_symbol(
            lambda _emulator, library, symbol, old: imported.append((library, symbol, old))
            or (int(replacement.pointer) if symbol == "dep_value" else None)
        )
        assert module_registration.active and not module_registration.removable
        assert import_registration.active and not import_registration.removable

        mapped: list[tuple[int, int, int]] = []
        protected: list[tuple[int, int, int]] = []
        unmapped: list[tuple[int, int]] = []
        mmap_listener = emulator.memory.listen_mmap(
            on_map=lambda address, size, protection: mapped.append(
                (address, size, protection)
            ),
            on_protect=lambda address, size, protection: protected.append(
                (address, size, protection)
            )
            or None,
            on_unmap=lambda address, size: unmapped.append((address, size)),
        )

        emulator.set_system_property_provider(
            lambda key: "py-value" if key == "ro.test.key" else None
        )
        module = emulator.load_library(FIXTURE)
        assert "libdep.so" in loaded
        assert loaded[-1] == "libadd.so"
        assert any(symbol == "dep_value" for _, symbol, _ in imported)
        assert int(module.call_symbol("call_dependency")) == 66

        mapping = emulator.memory.mmap(4096, 3)
        address = int(mapping)
        emulator.memory.mprotect(address, 4096, 1)
        emulator.memory.munmap(address, 4096)
        assert mapped[-1] == (address, 4096, 3)
        assert protected[-1] == (address, 4096, 1)
        assert unmapped[-1] == (address, 4096)
        mmap_listener.close()
        assert not mmap_listener.active

        key = emulator.memory.malloc(32)
        key.pointer.write(b"ro.test.key\0")
        value = emulator.memory.malloc(128)
        assert int(module.call_symbol("call_system_property", key.pointer, value.pointer)) == 8
        assert value.pointer.java.getString(0) == "py-value"

        tracker = emulator.track_memory_leaks()
        leaked = emulator.memory.mmap(4096, 3)
        assert tracker.total_allocations == 1
        assert tracker.total_leaked_size == 4096
        assert len(tracker.leaks) == 1
        emulator.memory.munmap(int(leaked), 4096)
        assert tracker.total_deallocations == 1
        assert tracker.total_leaked_size == 0
        tracker.close()


def test_inline_hook_engines() -> None:
    script = Path(__file__).parent / "run_inline_hook_checks.py"
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_hook_callback_errors_keep_original_python_exception() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.hook-errors") as emulator:
        module = emulator.load_library(FIXTURE)

        def fail(*_args):
            raise ValueError("hook boom")

        emulator.hooks.code(fail, begin=module.base, end=module.base + module.size)
        with pytest.raises(ValueError, match="hook boom"):
            module.call_symbol("add_numbers", 1, 2)
