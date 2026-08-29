from __future__ import annotations

import json
from pathlib import Path

import pytest

import pyunidbg


def test_guest_thread_dispatcher_and_signal_sets() -> None:
    with pyunidbg.AndroidEmulator("io.pyunidbg.threads") as emulator:
        assert not emulator.threads.enabled
        emulator.threads.enabled = True
        assert emulator.threads.enabled
        assert emulator.threads.task_count == 0
        assert emulator.threads.tasks == ()
        assert emulator.threads.running_task is None
        with pytest.raises(ValueError, match="positive"):
            emulator.threads.run_for(0)
        with pytest.raises(RuntimeError, match="no tasks"):
            emulator.threads.run_for(1)

        signals = emulator.threads.signal_set()
        signals.add(2)
        assert signals.contains(2)
        assert list(signals) == [2]
        signals.remove(2)
        assert not signals.contains(2)
        signals.block(1 << 2)
        signals.unblock(1 << 2)


def test_inspection_report_is_bounded_and_json_serializable(tmp_path: Path) -> None:
    fixture = Path(__file__).parent / "fixtures" / "libtrace.so"
    with pyunidbg.AndroidEmulator("io.pyunidbg.inspect") as emulator:
        emulator.load_library(fixture)
        allocation = emulator.memory.malloc(16)
        allocation.pointer.write(b"hello")
        report = emulator.inspect_state(
            memory_ranges=((int(allocation.pointer), 5),), max_capture_size=16
        )
        assert report.architecture == "ARM64"
        assert report.backend == "UnicornBackend"
        assert report.memory[0].hex == b"hello".hex()
        assert any(module["name"] == "libtrace.so" for module in report.modules)
        encoded = report.to_json()
        assert json.loads(encoded)["process_name"] == "io.pyunidbg.inspect"
        destination = report.save(tmp_path / "inspection.json")
        assert destination.read_text() == encoded

        with pytest.raises(ValueError, match="limit"):
            emulator.inspect_state(
                memory_ranges=((int(allocation.pointer), 17),), max_capture_size=16
            )

        assert not hasattr(emulator, "restore_state")
        assert not hasattr(emulator, "dump_state")
