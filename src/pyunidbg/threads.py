from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Any, ClassVar

import jpype


class SignalSet:
    def __init__(self, java: Any):
        self.java = java

    @property
    def mask(self) -> int:
        return int(self.java.getMask())

    @mask.setter
    def mask(self, value: int) -> None:
        self.java.setMask(jpype.JLong(value))

    def block(self, mask: int) -> None:
        self.java.blockSigSet(jpype.JLong(mask))

    def unblock(self, mask: int) -> None:
        self.java.unblockSigSet(jpype.JLong(mask))

    def contains(self, signal: int) -> bool:
        return bool(self.java.containsSigNumber(int(signal)))

    def add(self, signal: int) -> None:
        if signal <= 0:
            raise ValueError("signal number must be positive")
        self.mask |= 1 << (int(signal) - 1)

    def remove(self, signal: int) -> None:
        if signal <= 0:
            raise ValueError("signal number must be positive")
        self.mask &= ~(1 << (int(signal) - 1))

    def __iter__(self) -> Iterator[int]:
        return (int(signal) for signal in self.java)


@dataclass(frozen=True, slots=True)
class GuestTaskInfo:
    id: int
    main: bool
    finished: bool
    dispatchable: bool
    context_saved: bool
    status: str


class GuestTask:
    def __init__(self, emulator: Any, java: Any):
        self._emulator = emulator
        self.java = java

    @property
    def id(self) -> int:
        return int(self.java.getId())

    @property
    def main(self) -> bool:
        return bool(self.java.isMainThread())

    @property
    def finished(self) -> bool:
        return bool(self.java.isFinish())

    @property
    def dispatchable(self) -> bool:
        return bool(self.java.canDispatch())

    @property
    def context_saved(self) -> bool:
        return bool(self.java.isContextSaved())

    @property
    def waiter(self) -> Any:
        return self.java.getWaiter()

    @property
    def signal_mask(self) -> SignalSet | None:
        value = self.java.getSigMaskSet()
        return None if value is None else SignalSet(value)

    @property
    def pending_signals(self) -> SignalSet | None:
        value = self.java.getSigPendingSet()
        return None if value is None else SignalSet(value)

    @property
    def signal_tasks(self) -> tuple[Any, ...]:
        return tuple(self.java.getSignalTaskList())

    def set_errno(self, value: int) -> bool:
        return bool(self.java.setErrno(self._emulator.java, int(value)))

    def set_result(self, value: int) -> None:
        self.java.setResult(self._emulator.java, jpype.JLong(value))

    def set_destroy_listener(self, callback: Callable[[Any], None] | None) -> None:
        if callback is None:
            self.java.setDestroyListener(None)
            return
        owner = self

        class Listener:
            def onDestroy(self, raw_emulator: Any) -> None:
                try:
                    callback(owner._emulator)
                except BaseException as error:
                    owner._emulator._capture_callback_error(error)
                    raise

        implementation = Listener()
        proxy = jpype.JProxy(
            self._emulator._class("com.github.unidbg.thread.DestroyListener"),
            inst=implementation,
        )
        self.java.setDestroyListener(proxy)
        self._emulator._callback_refs.extend((implementation, proxy, callback))

    def set_waiter(
        self,
        can_dispatch: Callable[[], bool],
        on_continue: Callable[[Any], None],
        on_signal: Callable[[Any], None] | None = None,
    ) -> None:
        owner = self

        class Waiter:
            def canDispatch(self) -> bool:
                return bool(can_dispatch())

            def onContinueRun(self, raw_emulator: Any) -> None:
                on_continue(owner._emulator)

            def onSignal(self, signal_task: Any) -> None:
                if on_signal is not None:
                    on_signal(signal_task)

        implementation = Waiter()
        proxy = jpype.JProxy(
            self._emulator._class("com.github.unidbg.thread.Waiter"), inst=implementation
        )
        self.java.setWaiter(self._emulator.java, proxy)
        self._emulator._callback_refs.extend(
            (implementation, proxy, can_dispatch, on_continue, on_signal)
        )

    def snapshot(self) -> GuestTaskInfo:
        return GuestTaskInfo(
            id=self.id,
            main=self.main,
            finished=self.finished,
            dispatchable=self.dispatchable,
            context_saved=self.context_saved,
            status=str(self.java),
        )


class GuestThreadDispatcher:
    _UNITS: ClassVar[dict[str, str]] = {
        "nanoseconds": "NANOSECONDS",
        "microseconds": "MICROSECONDS",
        "milliseconds": "MILLISECONDS",
        "seconds": "SECONDS",
        "minutes": "MINUTES",
    }

    def __init__(self, emulator: Any):
        self._emulator = emulator
        self.java = emulator.java.getThreadDispatcher()
        self._enabled = False

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._emulator.syscalls.enable_thread_dispatcher(bool(value))
        self._enabled = bool(value)

    @property
    def tasks(self) -> tuple[GuestTask, ...]:
        return tuple(GuestTask(self._emulator, task) for task in self.java.getTaskList())

    @property
    def task_count(self) -> int:
        return int(self.java.getTaskCount())

    @property
    def running_task(self) -> GuestTask | None:
        task = self.java.getRunningTask()
        return None if task is None else GuestTask(self._emulator, task)

    @property
    def main_signal_mask(self) -> SignalSet | None:
        if not hasattr(self.java, "getSigMaskSet"):
            return None
        value = self.java.getSigMaskSet()
        return None if value is None else SignalSet(value)

    @main_signal_mask.setter
    def main_signal_mask(self, value: SignalSet) -> None:
        self.java.setSigMaskSet(value.java)

    @property
    def main_pending_signals(self) -> SignalSet | None:
        if not hasattr(self.java, "getSigPendingSet"):
            return None
        value = self.java.getSigPendingSet()
        return None if value is None else SignalSet(value)

    @main_pending_signals.setter
    def main_pending_signals(self, value: SignalSet) -> None:
        self.java.setSigPendingSet(value.java)

    def signal_set(self, mask: int = 0) -> SignalSet:
        return SignalSet(
            self._emulator._class("com.github.unidbg.signal.UnixSigSet")(
                jpype.JLong(mask)
            )
        )

    def run_for(self, duration: float, *, unit: str = "milliseconds") -> None:
        if duration <= 0:
            raise ValueError("duration must be positive")
        if self.task_count == 0:
            raise RuntimeError("cannot run guest threads because no tasks are scheduled")
        try:
            java_unit = self._emulator._class("java.util.concurrent.TimeUnit").valueOf(
                self._UNITS[unit]
            )
        except KeyError as error:
            raise ValueError(f"unsupported time unit: {unit}") from error
        self._emulator._run_checked(
            lambda: self.java.runThreads(int(duration), java_unit)
        )

    def emulate_signal(self, signal: int) -> bool:
        return bool(
            self._emulator._run_checked(
                lambda: self._emulator.java.emulateSignal(int(signal))
            )
        )

    def send_signal(self, task_id: int, signal: int, signal_task: Any) -> bool:
        raw = signal_task.java if hasattr(signal_task, "java") else signal_task
        return bool(self.java.sendSignal(int(task_id), int(signal), raw))

    def add_raw_task(self, task: Any) -> None:
        self.java.addThread(task.java if hasattr(task, "java") else task)
