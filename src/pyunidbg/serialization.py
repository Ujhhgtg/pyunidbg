from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class MemoryCapture:
    address: int
    size: int
    hex: str


@dataclass(frozen=True, slots=True)
class InspectionReport:
    created_at: str
    process_name: str
    backend: str
    architecture: str
    registers: dict[str, str]
    modules: tuple[dict[str, Any], ...]
    memory_maps: tuple[dict[str, Any], ...]
    tasks: tuple[dict[str, Any], ...]
    breakpoints: tuple[str, ...]
    memory: tuple[MemoryCapture, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path, *, indent: int = 2) -> Path:
        return save_inspection_report(self, path, indent=indent)


def save_inspection_report(
    report: InspectionReport, path: str | Path, *, indent: int = 2
) -> Path:
    destination = Path(path).resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(report.to_json(indent=indent).encode())
            file.flush()
            os.fsync(file.fileno())
        temporary.replace(destination)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


def inspect_emulator_state(
    emulator: Any,
    *,
    memory_ranges: tuple[tuple[int, int], ...] = (),
    max_capture_size: int = 1024 * 1024,
) -> InspectionReport:
    total = sum(size for _, size in memory_ranges)
    if total > max_capture_size:
        raise ValueError(
            f"requested memory capture is {total} bytes; limit is {max_capture_size}"
        )
    constants = emulator._class("unicorn.Arm64Const")
    register_names = [f"X{index}" for index in range(31)] + ["SP", "PC", "NZCV"]
    registers = {
        name.lower(): f"0x{int(emulator.backend.reg_read(int(getattr(constants, f'UC_ARM64_REG_{name}')))):x}"
        for name in register_names
    }
    modules = tuple(
        {
            "name": str(module.name),
            "base": f"0x{int(module.base):x}",
            "size": int(module.size),
            "path": str(module.getPath()),
        }
        for module in emulator.memory.java.getLoadedModules()
    )
    maps = tuple(
        {
            "base": f"0x{int(mapping.base):x}",
            "size": int(mapping.size),
            "protection": int(mapping.prot),
        }
        for mapping in emulator.memory.java.getMemoryMap()
    )
    tasks = tuple(asdict(task.snapshot()) for task in emulator.threads.tasks)
    breakpoints = tuple(
        f"0x{int(entry.getKey()):x}"
        for entry in emulator.java.attach().getBreakPoints().entrySet()
    )
    captures = tuple(
        MemoryCapture(address, size, emulator.memory.read(address, size).hex())
        for address, size in memory_ranges
    )
    return InspectionReport(
        created_at=datetime.now(UTC).isoformat(),
        process_name=str(emulator.java.getProcessName()),
        backend=str(emulator.backend.getClass().getSimpleName()),
        architecture="ARM64",
        registers=registers,
        modules=modules,
        memory_maps=maps,
        tasks=tasks,
        breakpoints=breakpoints,
        memory=captures,
    )
