from __future__ import annotations

from pathlib import Path
import subprocess
import sys

import jpype

import pyunidbg

FIXTURE = Path(__file__).parent / "fixtures" / "libadd.so"


class FullJniHandler(pyunidbg.JniHandler):
    def __init__(self) -> None:
        self.events: list[tuple[str, str, object]] = []

    def handle_jni(self, operation, vm, target, signature, args, value):
        self.events.append((operation, signature, value))
        results = {
            "get_static_int_field": 123,
            "get_float_field": 1.5,
            "set_long_field": None,
            "accept_method": False,
        }
        return results.get(operation, pyunidbg.NOT_HANDLED)


def test_previous_partial_feature_families(tmp_path: Path) -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.coverage", root_dir=tmp_path / "root") as emulator:
        # Filesystem, syscall, IO, and asset resolver coverage.
        emulator.add_io_resolver(
            lambda _emulator, path, _flags: b"virtual-data" if path == "/virtual" else None
        )
        descriptor = emulator.syscalls.open("/virtual")
        assert descriptor >= 0
        assert str(emulator.syscalls.file_io(descriptor)) == "/virtual"
        emulator.syscalls.close(descriptor)
        emulator.vm.set_asset_resolver(lambda name: b"asset:" + name.encode())
        assert bytes(emulator.vm.java.openAsset("sample")) == b"asset:sample"
        assert emulator.filesystem.mkdir("/created")
        assert (emulator.filesystem.root_dir / "created").is_dir()
        assert emulator.filesystem.rename("/created", "/renamed") == 0
        emulator.filesystem.rmdir("/renamed")

        # Complete module/symbol inspection conveniences.
        module = emulator.load_library(FIXTURE)
        symbol = module.find_symbol("add_numbers")
        assert symbol is not None
        assert symbol.name == "add_numbers"
        assert symbol.module_name == "libadd.so"
        assert symbol.address >= module.base
        assert int(symbol.call(4, 5)) == 9
        assert module.closest_symbol(symbol.address).name == "add_numbers"
        assert module.path == "libadd.so"
        assert module.file_size == FIXTURE.stat().st_size
        assert module.size > 0
        assert module.regions
        assert {item.name for item in module.exported_symbols} >= {
            "add_numbers",
            "read_number",
            "write_number",
        }

        # Read, write, and instruction trace callbacks plus debugger wrapper.
        allocation = emulator.memory.malloc(16)
        allocation.pointer.write_u64(0, 9)
        reads: list[tuple[int, bytes]] = []
        writes: list[tuple[int, int, int]] = []
        read_trace = emulator.trace_read(
            lambda _emulator, address, data, _label: not reads.append((address, data)),
            begin=int(allocation.pointer),
            end=int(allocation.pointer) + 8,
        ).redirect(tmp_path / "read-trace.txt")
        write_trace = emulator.trace_write(
            lambda _emulator, address, size, value: not writes.append((address, size, value)),
            begin=int(allocation.pointer),
            end=int(allocation.pointer) + 8,
        ).redirect(tmp_path / "write-trace.txt")
        try:
            assert int(module.call_symbol("read_number", allocation.pointer)) == 9
            module.call_symbol("write_number", allocation.pointer, 17)
        finally:
            read_trace.stop()
            write_trace.stop()
        assert reads and reads[-1][1] == (9).to_bytes(8, "little")
        assert writes and writes[-1][1:] == (8, 17)
        debugger = emulator.debugger()
        assert not debugger.debugging
        assert debugger.breakpoints == {}
        debugger.set_debug_filter(lambda _emulator, _history: True)
        debugger.trace_function_calls(lambda _emulator, _caller, _function: None, module=module)

        # Generic dispatch completes the remaining unidbg Jni callback families.
        handler = FullJniHandler()
        emulator.vm.set_jni(handler)
        bridge = emulator.vm._jni_references[0]
        clazz = emulator.vm.resolve_class("x/Coverage")
        obj = clazz.new_object()
        string = jpype.JString
        assert bridge.getStaticIntField(
            emulator.vm.java, clazz.java, string("x/Coverage->number:I")
        ) == 123
        assert bridge.getFloatField(
            emulator.vm.java, obj.java, string("x/Coverage->ratio:F")
        ) == 1.5
        bridge.setLongField(
            emulator.vm.java, obj.java, string("x/Coverage->count:J"), jpype.JLong(9)
        )
        assert not bridge.acceptMethod(clazz.java, string("x/Coverage->run()V"), True)
        assert {event[0] for event in handler.events} == {
            "get_static_int_field",
            "get_float_field",
            "set_long_field",
            "accept_method",
        }


def test_code_trace_in_fresh_process() -> None:
    script = Path(__file__).parent / "run_code_trace_check.py"
    result = subprocess.run(
        [sys.executable, str(script)], capture_output=True, text=True, timeout=30
    )
    assert result.returncode == 0, result.stdout + result.stderr
