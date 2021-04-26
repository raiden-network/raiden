import atexit
import signal
from abc import ABC, abstractmethod
from types import TracebackType
from typing import Any, Callable, List, Optional, Set, Type

import gevent
import structlog
from gevent import Greenlet, GreenletExit
from gevent.event import AsyncResult
from gevent.greenlet import SpawnedLink
from gevent.lock import RLock
from gevent.subprocess import Popen, TimeoutExpired

log = structlog.get_logger(__name__)
STATUS_CODE_FOR_SUCCESS = 0


class Nursery(ABC):
    @abstractmethod
    def exec_under_watch(self, process_args: List[str], **kwargs: Any) -> Optional[Popen]:
        pass

    @abstractmethod
    def spawn_under_watch(self, function: Callable, *args: Any, **kargs: Any) -> Greenlet:
        pass

    @abstractmethod
    def wait(self, timeout: Optional[float]) -> None:
        pass


class Janitor:
    """Janitor to properly cleanup after spawned subprocesses and greenlets.

    The goal of the janitor is to:

    - Propagate errors, if any of the watched processes / greenlets fails.
    - Keep track of spawned subprocesses and greenlets and make sure that
      everything is cleanup once the Janitor is done.
        - If the janitor is exiting because the monitored block is done (i.e.
          the with block is done executing), then a "clean" shutdown is
          performed.
        - Otherwise an exception occurred and the greenlets are killed it.
    """

    def __init__(self, stop_timeout: float = 20) -> None:
        self.stop_timeout = stop_timeout
        self._stop = AsyncResult()
        self._processes: Set[Popen] = set()
        self._exit_in_progress = False

        # Lock to protect changes to `_stop` and `_processes`. The `_stop`
        # synchronization is necessary to fix the race described below,
        # `_processes` synchronization is necessary to avoid iteration over a
        # changing container.
        #
        # Important: It is very important to register any executed subprocess,
        # otherwise no signal will be sent during shutdown and the subprocess
        # will become orphan. To properly register the subprocesses it is very
        # important to finish any pending call to `exec_under_watch` before
        # exiting the `Janitor`, and if the exit does run, `exec_under_watch`
        # must not start a new process.
        #
        # Note this only works if the greenlet that instantiated the Janitor
        # itself has a chance to run.
        self._processes_lock = RLock()

    def __enter__(self) -> Nursery:
        # Registers an atexit callback in case the __exit__ doesn't get a
        # chance to run. This happens when the Janitor is not used in the main
        # greenlet, and its greenlet is not the one that is dying.
        atexit.register(self._free_resources)

        # Hide the nursery to require the context manager to be used. This
        # leads to better behavior in the happy case since the exit handler is
        # used.
        janitor = self

        class ProcessNursery(Nursery):
            @staticmethod
            def exec_under_watch(process_args: List[str], **kwargs: Any) -> Optional[Popen]:
                msg = (
                    "The Janitor can not work with `shell=True`. When that flag "
                    "is used a proxy shell process is used to start the real "
                    "target process, the result is that the Janitor will monitor "
                    "and kill the proxy shell instead of the target, once the "
                    "shell is killed the real targets are kept around as "
                    "orphans, which is exactly what the Janitor is trying to "
                    "prevent from happening."
                )
                assert not kwargs.get("shell", False), msg

                def subprocess_stopped(result: AsyncResult) -> None:
                    if janitor._exit_in_progress:
                        # During __exit__ we expect processes to stop, since
                        # they are killed by the janitor.
                        return

                    with janitor._processes_lock:
                        # Processes are expected to quit while the nursery is
                        # active, remove them from the track list to clear memory
                        janitor._processes.remove(process)

                        # if the subprocess error'ed propagate the error.
                        try:
                            exit_code = result.get()
                            if exit_code != STATUS_CODE_FOR_SUCCESS:
                                log.error(
                                    "Process died! Bailing out.",
                                    args=process.args,
                                    exit_code=exit_code,
                                )
                                exception = SystemExit(exit_code)
                                janitor._stop.set_exception(exception)
                        except Exception as exception:
                            log.exception(
                                "Process erroed! Propagating error.",
                                args=process.args,
                            )
                            janitor._stop.set_exception(exception)

                with janitor._processes_lock:
                    if janitor._stop.ready():
                        return None

                    process = Popen(process_args, **kwargs)
                    janitor._processes.add(process)

                    # `rawlink`s are executed from within the hub, the problem
                    # is that locks can not be acquire at that point.
                    # SpawnedLink creates a new greenlet to run the callback to
                    # circumvent that.
                    callback = SpawnedLink(subprocess_stopped)

                    process.result.rawlink(callback)

                    # Important: `stop` may be set after Popen started, but before
                    # it returned. If that happens `GreenletExit` exception is
                    # raised here. In order to have proper cleared, exceptions have
                    # to be handled and the process installed.
                    if janitor._stop.ready():
                        process.send_signal(signal.SIGINT)

                    return process

            @staticmethod
            def spawn_under_watch(function: Callable, *args: Any, **kwargs: Any) -> Greenlet:
                greenlet = gevent.spawn(function, *args, **kwargs)

                # The callback provided to `AsyncResult.rawlink` is executed
                # inside the Hub thread, the callback is calling `throw` which
                # has to be called from the Hub, so here there is no need to
                # wrap the callback in a SpawnedLink.
                #
                # `throw` does not raise the exception if the greenlet has
                # finished, which is exactly the semantics needed here.
                def stop_greenlet_from_hub(result: AsyncResult) -> None:
                    """Stop the greenlet if the nursery is stopped."""
                    try:
                        result.get()
                    except BaseException as e:
                        greenlet.throw(e)
                    else:
                        greenlet.throw(GreenletExit())

                def propagate_error(g: Greenlet) -> None:
                    """If the greenlet fails, stop the nursery."""
                    janitor._stop.set_exception(g.exception)

                greenlet.link_exception(propagate_error)
                janitor._stop.rawlink(stop_greenlet_from_hub)

                return greenlet

            @staticmethod
            def wait(timeout: Optional[float]) -> None:
                janitor._stop.wait(timeout)

        return ProcessNursery()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        self._exit_in_progress = True
        with self._processes_lock:
            # Make sure to signal that we are exiting.
            if not self._stop.done():
                self._stop.set()

            self._free_resources()

            # Behave nicely if context manager's __exit__ is executed. This
            # implements the expected behavior of a context manager, which will
            # clear the resources when exiting.
            atexit.unregister(self._free_resources)

        self._stop.get()
        return None

    def _free_resources(self) -> None:
        with self._processes_lock:
            for p in self._processes:
                p.send_signal(signal.SIGINT)

            try:
                for p in self._processes:
                    exit_code = p.wait(timeout=self.stop_timeout)
                    if exit_code != STATUS_CODE_FOR_SUCCESS:
                        log.warning(
                            "Process did not exit cleanly",
                            exit_code=exit_code,
                            communicate=p.communicate(),
                        )
            except TimeoutExpired:
                log.warning(
                    "Process did not stop in time. Sending SIGKILL to all remaining processes!",
                    command=p.args,
                )
                for p in self._processes:
                    p.send_signal(signal.SIGKILL)
