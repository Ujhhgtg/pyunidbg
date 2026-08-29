from __future__ import annotations

import asyncio
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import pytest

import pyunidbg


@dataclass
class FakeWorker:
    number: int
    closed: bool = False

    def close(self) -> None:
        self.closed = True


def test_worker_pool_lifecycle_contention_and_invalidation() -> None:
    created: list[FakeWorker] = []

    def factory() -> FakeWorker:
        worker = FakeWorker(len(created))
        created.append(worker)
        return worker

    pool = pyunidbg.WorkerPool(factory, max_size=2, idle_timeout=None)
    assert pool.stats.created == 0
    active = 0
    maximum_active = 0
    lock = threading.Lock()

    def operation(_: int) -> int:
        nonlocal active, maximum_active
        with pool.borrow(timeout=2) as worker:
            with lock:
                active += 1
                maximum_active = max(maximum_active, active)
            time.sleep(0.02)
            with lock:
                active -= 1
            return worker.number

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(operation, range(20)))
    assert set(results) <= {0, 1}
    assert maximum_active == 2
    assert pool.stats.created == 2
    assert pool.stats.idle == 2

    lease = pool.borrow()
    invalidated = lease.worker
    lease.invalidate()
    lease.close()
    assert invalidated.closed
    assert pool.stats.invalidated == 1
    assert pool.stats.created == 1

    pool.close()
    assert pool.stats.closed
    assert all(worker.closed for worker in created)
    with pytest.raises(pyunidbg.PoolClosedError):
        pool.borrow()


def test_worker_pool_timeout_idle_cleanup_and_async() -> None:
    destroyed: list[int] = []
    next_number = iter(range(100))
    pool = pyunidbg.WorkerPool(
        lambda: FakeWorker(next(next_number)),
        max_size=1,
        idle_timeout=0.05,
        destroy=lambda worker: destroyed.append(worker.number),
    )
    lease = pool.borrow()
    with pytest.raises(pyunidbg.BorrowTimeoutError):
        pool.borrow(timeout=0.01)
    lease.close()
    deadline = time.monotonic() + 1
    while pool.stats.created and time.monotonic() < deadline:
        time.sleep(0.02)
    assert pool.stats.created == 0
    assert destroyed

    assert asyncio.run(pool.run_async(lambda worker: worker.number, timeout=1)) >= 0
    pool.close()


def test_real_emulator_workers_are_exclusive_and_reusable() -> None:
    fixture = Path(__file__).parent / "fixtures" / "libtrace.so"

    @dataclass
    class NativeWorker:
        emulator: pyunidbg.AndroidEmulator
        module: pyunidbg.Module

        def close(self) -> None:
            self.emulator.close()

    def factory() -> NativeWorker:
        emulator = pyunidbg.AndroidEmulator("io.pyunidbg.pool")
        return NativeWorker(emulator, emulator.load_library(fixture))

    with pyunidbg.WorkerPool(factory, max_size=2, idle_timeout=None) as pool:
        def add(pair: tuple[int, int]) -> int:
            return pool.run(
                lambda worker: int(worker.module.call_symbol("traced_add", *pair)),
                timeout=5,
            )

        with ThreadPoolExecutor(max_workers=4) as executor:
            results = list(executor.map(add, [(index, index + 1) for index in range(12)]))
        assert results == [index + index + 1 for index in range(12)]
        assert pool.stats.created == 2
        assert pool.stats.idle == 2
