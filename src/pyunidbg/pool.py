from __future__ import annotations

import asyncio
import threading
import time
from collections import deque
from collections.abc import Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from types import TracebackType
from typing import Any, Self, TypeVar, cast

T = TypeVar("T")
R = TypeVar("R")


class PoolClosedError(RuntimeError):
    pass


class BorrowTimeoutError(TimeoutError):
    pass


@dataclass(frozen=True, slots=True)
class PoolStats:
    created: int
    borrowed: int
    idle: int
    pending: int
    invalidated: int
    closed: bool


@dataclass(slots=True)
class EmulatorWorker:
    emulator: Any
    state: object = None

    def close(self) -> None:
        self.emulator.close()


@dataclass(slots=True)
class _IdleWorker[T]:
    worker: T
    returned_at: float


class WorkerLease[T](AbstractContextManager[T]):
    def __init__(self, pool: WorkerPool[T], worker: T):
        self._pool = pool
        self.worker = worker
        self._invalid = False
        self._closed = False

    def invalidate(self) -> None:
        self._invalid = True

    def close(self) -> None:
        if not self._closed:
            self._pool._return(self.worker, invalid=self._invalid)
            self._closed = True

    def __enter__(self) -> T:
        return self.worker

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class WorkerPool[T]:
    def __init__(
        self,
        factory: Callable[[], T],
        *,
        max_size: int,
        initial_size: int = 0,
        min_idle: int = 0,
        idle_timeout: float | None = 600,
        destroy: Callable[[T], None] | None = None,
    ):
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        if not 0 <= min_idle <= max_size:
            raise ValueError("min_idle must be between zero and max_size")
        if not 0 <= initial_size <= max_size:
            raise ValueError("initial_size must be between zero and max_size")
        self._factory = factory
        self._destroy_callback = destroy
        self._max_size = max_size
        self._min_idle = min_idle
        self._idle_timeout = idle_timeout
        self._condition = threading.Condition()
        self._idle: deque[_IdleWorker[T]] = deque()
        self._created = 0
        self._borrowed = 0
        self._pending = 0
        self._invalidated = 0
        self._closed = False
        self._reaper_stop = threading.Event()
        self._reaper = threading.Thread(
            target=self._reap_loop, name="pyunidbg-worker-reaper", daemon=True
        )
        self._reaper.start()
        for _ in range(max(initial_size, min_idle)):
            self._idle.append(_IdleWorker(self._create_reserved(), time.monotonic()))

    def _create_reserved(self) -> T:
        with self._condition:
            if self._created >= self._max_size:
                raise RuntimeError("worker capacity exhausted")
            self._created += 1
        try:
            return self._factory()
        except BaseException:
            with self._condition:
                self._created -= 1
                self._condition.notify_all()
            raise

    def borrow(self, timeout: float | None = None) -> WorkerLease[T]:
        deadline = None if timeout is None else time.monotonic() + timeout
        create = False
        with self._condition:
            if self._closed:
                raise PoolClosedError("worker pool is closed")
            self._pending += 1
            try:
                while True:
                    if self._closed:
                        raise PoolClosedError("worker pool is closed")
                    if self._idle:
                        worker = self._idle.pop().worker
                        self._borrowed += 1
                        return WorkerLease(self, worker)
                    if self._created < self._max_size:
                        self._created += 1
                        self._borrowed += 1
                        create = True
                        break
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        raise BorrowTimeoutError("timed out waiting for a worker")
                    self._condition.wait(remaining)
            finally:
                self._pending -= 1
        if create:
            try:
                return WorkerLease(self, self._factory())
            except BaseException:
                with self._condition:
                    self._created -= 1
                    self._borrowed -= 1
                    self._condition.notify_all()
                raise
        raise AssertionError("unreachable")

    def _return(self, worker: T, *, invalid: bool) -> None:
        destroy = False
        with self._condition:
            self._borrowed -= 1
            if invalid:
                self._created -= 1
                self._invalidated += 1
                destroy = True
            elif self._closed:
                self._created -= 1
                destroy = True
            else:
                self._idle.append(_IdleWorker(worker, time.monotonic()))
            self._condition.notify_all()
        if destroy:
            self._destroy(worker)

    def _destroy(self, worker: T) -> None:
        if self._destroy_callback is not None:
            self._destroy_callback(worker)
            return
        close = getattr(worker, "close", None)
        if callable(close):
            close()
            return
        destroy = getattr(worker, "destroy", None)
        if callable(destroy):
            destroy()

    def _reap_loop(self) -> None:
        while not self._reaper_stop.wait(0.25):
            if self._idle_timeout is None:
                continue
            expired: list[T] = []
            now = time.monotonic()
            with self._condition:
                while (
                    len(self._idle) > self._min_idle
                    and self._idle
                    and now - self._idle[0].returned_at >= self._idle_timeout
                ):
                    expired.append(self._idle.popleft().worker)
                    self._created -= 1
                if expired:
                    self._condition.notify_all()
            for worker in expired:
                self._destroy(worker)

    def run(self, operation: Callable[[T], R], *, timeout: float | None = None) -> R:
        with self.borrow(timeout) as worker:
            return operation(worker)

    async def run_async(
        self, operation: Callable[[T], R], *, timeout: float | None = None
    ) -> R:
        return cast(R, await asyncio.to_thread(self.run, operation, timeout=timeout))

    @property
    def stats(self) -> PoolStats:
        with self._condition:
            return PoolStats(
                created=self._created,
                borrowed=self._borrowed,
                idle=len(self._idle),
                pending=self._pending,
                invalidated=self._invalidated,
                closed=self._closed,
            )

    def close(self, *, wait: bool = True, timeout: float | None = None) -> None:
        deadline = None if timeout is None else time.monotonic() + timeout
        timed_out = False
        with self._condition:
            if self._closed:
                return
            self._closed = True
            self._condition.notify_all()
            if wait:
                while self._borrowed:
                    remaining = None if deadline is None else deadline - time.monotonic()
                    if remaining is not None and remaining <= 0:
                        timed_out = True
                        break
                    self._condition.wait(remaining)
            idle = [item.worker for item in self._idle]
            self._created -= len(idle)
            self._idle.clear()
        self._reaper_stop.set()
        self._reaper.join(timeout=1)
        for worker in idle:
            self._destroy(worker)
        if timed_out:
            raise TimeoutError("timed out waiting for borrowed workers")

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()
