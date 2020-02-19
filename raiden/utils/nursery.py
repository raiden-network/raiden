import atexit
import signal
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, Callable, List, Optional, Set, Type

import gevent
import structlog
from gevent.event import AsyncResult, Event
from gevent.greenlet import Greenlet
from gevent.subprocess import Popen

log = structlog.get_logger(__name__)
STATUS_CODE_FOR_SUCCESS = 0


class Nursery(ABC):
    @abstractmethod
    def exec_under_watch(self, process: Popen) -> None:
        pass

    @abstractmethod
    def spawn_under_watch(self, function: Callable, *args: Any, **kargs: Any) -> Greenlet:
        pass


class Janitor:
    """Tries to properly stop all subprocesses before quitting the script.

    - This watches for the status of the subprocess, if the processes exits
      with a non-zero error code then the failure is propagated.
    - If for any reason this process is dying, then all the spawned processes
      have to be killed in order for a proper clean up to happen.
    """

    def __init__(self, stop: Event) -> None:
        self.stop = stop
        self._processes: Set[Popen] = set()

    def __enter__(self) -> Nursery:
        # Registers an atexit callback in case the __exit__ doesn't get a
        # chance to run. This happens when the Janitor is not used in the main
        # greenlet, and its greenlet is not the one that is dying.
        atexit.register(self._free_resources)

        # Hide the nursery to require the context manager to be used. This
        # leads to better behavior in the happy case since the exit handler is
        # used.
        janitor = self
        stop = self.stop

        class ProcessNursery(Nursery):
            @staticmethod
            def exec_under_watch(args: List[str]) -> None:
                # Important: It is possible for the process to start shutting
                # down after the Popen started but before it returned. If that
                # happens and this code is executed inside a greenlet spawned
                # with `spawn_under_watch` then a `GreenletExit` exception is
                # raised here.
                #
                # To make sure the subprocess is properly cleared, exceptions
                # have to be handled here.
                try:
                    process = Popen(args)
                finally:
                    janitor._processes.add(process)

                    def subprocess_stopped(result: AsyncResult) -> None:
                        # Processes are expected to quit while the nursery is
                        # active, remove them from the track list to clear memory
                        janitor._processes.remove(process)

                        # if the subprocess error'ed propagate the error.
                        if result.get() != STATUS_CODE_FOR_SUCCESS:
                            log.error("Proess died! Bailing out.")
                            stop.set()

                    process.result.rawlink(subprocess_stopped)

                    # Fix race condition were the stop was set while the process
                    # was started.
                    if self.stop.is_set():
                        process.send_signal(signal.SIGINT)

            @staticmethod
            def spawn_under_watch(function: Callable, *args: Any, **kwargs: Any) -> Greenlet:
                greenlet = gevent.spawn(function, *args, **kwargs)

                # The Event.rawlink is executed inside the Hub thread, which
                # does validation and *raises on blocking calls*, to go around
                # this a new greenlet has to be spawned, that in turn will
                # raise the exception.
                def spawn_to_kill() -> None:
                    gevent.spawn(greenlet.throw, gevent.GreenletExit())

                stop.rawlink(lambda _stop: spawn_to_kill())
                return greenlet

        return ProcessNursery()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        # Make sure to signal that we are exiting. This is a noop if the signal
        # is set already (e.g. because a subprocess exited with a non-zero
        # status code)
        self.stop.set()

        # Behave nicely if context manager's __exit__ is executed. This
        # implements the expected behavior of a context manager, which will
        # clear the resources when exiting.
        atexit.unregister(self._free_resources)

        self._free_resources()

        return None

    def _free_resources(self) -> None:
        for p in self._processes:
            p.send_signal(signal.SIGINT)

        for p in self._processes:
            if p.wait() != STATUS_CODE_FOR_SUCCESS:
                print("Process did not exit cleanly", p.communicate())
