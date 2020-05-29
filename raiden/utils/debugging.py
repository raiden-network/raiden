import signal
import time
from dataclasses import dataclass, field
from typing import Any, List, Optional

import gevent
import gevent.util
import structlog
from gevent._tracer import GreenletTracer
from gevent.hub import Hub

from raiden.exceptions import RaidenUnrecoverableError

LIBEV_LOW_PRIORITY = -2
LIBEV_HIGH_PRIORITY = 2
log = structlog.get_logger(__name__)


def enable_gevent_monitoring_signal() -> None:
    """ Install a signal handler for SIGUSR1 that executes gevent.util.print_run_info().
    This can help evaluating the gevent greenlet tree.
    See http://www.gevent.org/monitoring.html for more information.

    Usage:
        pytest [...]
        # while test is running (or stopped in a pdb session):
        kill -SIGUSR1 $(pidof -x pytest)
    """

    def on_signal(signalnum: Any, stack_frame: Any) -> None:  # pylint: disable=unused-argument
        gevent.util.print_run_info()

    signal.signal(signal.SIGUSR1, on_signal)


def limit_thread_cpu_usage_by_time() -> None:
    """This will enable Gevent's monitoring thread, and if a Greenlet uses the
    CPU for longer than `max_blocking_time` it will be killed.

    This will result in the whole process being killed, since exceptions are
    propagate to the top-level. The goal here is to detect slow functions that
    have to be optimized.
    """
    gevent.config.monitor_thread = True
    gevent.config.max_blocking_time = 10.0

    # The monitoring thread will use the trace api just like the TraceSampler
    # and the SwitchMonitoring. Sadly there is no API to uninstall the thread,
    # but this should not be a problem.
    monitor_thread = gevent.get_hub().start_periodic_monitoring_thread()

    # This code must not use the tracer from the monitor_thread because calls
    # to `did_block_hub` will reset its internal state. If two threads use the
    # same underlying tracer false positives will happen, because the switch
    # counter will be artifically reset.
    greenlet_tracer = GreenletTracer()

    def kill_offender(hub: Hub) -> None:
        if greenlet_tracer.did_block_hub(hub):
            active_greenlet = greenlet_tracer.active_greenlet

            msg = ""
            if monitor_thread._tracer.active_greenlet != active_greenlet:
                msg = (
                    f"Mismatch values for the active_greenlet among the "
                    f"monitor_thread and deubgging tracer, this either means "
                    f"there is a bug in the trace chain (the wrong values are "
                    f"forwarded), or that one of the trace functions was wrongly "
                    f"uninstalled. Active greenlets "
                    f"monitor_thread={monitor_thread._tracer.active_greenlet} "
                    f"debug_tracer={active_greenlet}."
                )

            hub.loop.run_callback(
                lambda: active_greenlet.throw(
                    RaidenUnrecoverableError(
                        f"A greenlet used the CPU for longer than "
                        f"{gevent.config.max_blocking_time} seconds, killing it.{msg}"
                    )
                )
            )

    monitor_thread.add_monitoring_function(kill_offender, gevent.config.max_blocking_time)


@dataclass
class IdleMeasurement:
    before_poll: float
    after_poll: float


@dataclass
class Idle:
    """ Measures how much time the thread waited on the libev backend. """

    measurement_interval: float
    before_poll: Optional[float] = None
    last_print: float = field(init=False, default_factory=time.time)
    measurements: List[IdleMeasurement] = field(init=False, default_factory=list)

    def prepare_handler(self) -> None:
        """ The prepare handler executed before the call to the polling backend
        (e.g. select/epoll).

        Note:
        - Gevent uses a prepare handler to execute deferred callbacks. This
          means there will be some work done on with this type of handler that
          must not added to the idle time. To avoid counting the time spent on
          the deferred callbacks the prepare_handler must be installed with a
          low priority, so that it executes after the gevent's callbacks.
        """
        self.before_poll = time.time()

    def check_handler(self) -> None:
        """ Check handler executed after the poll backend returns.

        Note:
        - For each of the watchers in the ready state there will be a callback,
          which will do work related to the watcher (e.g. read from a socket).
          This time must not be accounted for in the Idle timeout, therefore
          this handler must have a high priority.
        """
        curr_time = time.time()

        # It is possible for the check_handler to be executed before the
        # prepare_handler, this happens when the watchers are installed by a
        # greenlet that was switched onto because of IO (IOW, Idle.enable is
        # called while the event loop is executing watchers, after the `poll`)
        if self.before_poll is not None:
            self.measurements.append(  # pylint: disable=no-member
                IdleMeasurement(self.before_poll, curr_time)
            )

            # keep at least one measurement, this will tell if the code is
            # blocking for an extended period of time.
            while len(self.measurements) > 1 and self.running_interval > self.measurement_interval:
                self.measurements.pop()  # pylint: disable=no-member

        if curr_time - self.last_print >= self.measurement_interval:
            self.log()
            self.last_print = curr_time

    def enable(self) -> None:
        loop = gevent.get_hub().loop
        loop.prepare(priority=LIBEV_LOW_PRIORITY).start(self.prepare_handler)
        loop.check(priority=LIBEV_HIGH_PRIORITY).start(self.check_handler)

    @property
    def measurements_start(self) -> float:
        return self.measurements[0].before_poll

    @property
    def measurements_end(self) -> float:
        return self.measurements[-1].after_poll

    @property
    def running_interval(self) -> float:
        """ The number of seconds idled by this thread.

        This will take into account the measurements frequency. Ideally the
        measurements would happen exactly every `measurement_interval` seconds,
        however that dependends on the existing load for the given thread, if
        the event loop doesn't run often enough the running_interval  will be
        larger than the target `measurement_interval`.
        """
        return self.measurements_end - self.measurements_start

    @property
    def idled(self) -> float:
        """ The amount of seconds the thread idled. """
        return sum(interval.after_poll - interval.before_poll for interval in self.measurements)

    @property
    def idled_pct(self) -> float:
        """ The percentage of time the thread idled, waiting on the event loop. """
        return self.idled / self.running_interval

    @property
    def context_switches(self) -> int:
        """ The number of context switches done for the past `measurement_interval`. """
        return len(IDLE.measurements)

    def log(self) -> None:
        if not self.measurements:
            log.debug("No idle data", context_switches=self.context_switches)
            return

        is_blocking = (
            len(self.measurements) == 1 and self.running_interval > self.measurement_interval
        )
        if is_blocking:
            msg = "Blocking function, there is not a lot of idle time"
        else:
            msg = "Idle"

        log.debug(
            msg,
            start=self.measurements_start,
            context_switches=self.context_switches,
            idled=self.idled,
            interval=self.running_interval,
            idle_pct=self.idled_pct,
        )

    def __bool__(self) -> bool:
        return bool(self.measurements)

    def __str__(self) -> str:
        if not self.measurements:
            return ""

        return (
            f"The thread had {self.context_switches} context_switches, and "
            f"idled {self.idled_pct}% of the time."
        )


IDLE = Idle(10)
