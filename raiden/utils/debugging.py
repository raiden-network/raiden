import signal
from typing import Any

import gevent
import gevent.util
from gevent.hub import Hub

from raiden.exceptions import RaidenUnrecoverableError


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

    def kill_offender(hub: Hub) -> None:
        tracer = monitor_thread._greenlet_tracer

        if tracer.did_block_hub(hub):
            active_greenlet = tracer.active_greenlet
            hub.loop.run_callback(
                lambda: active_greenlet.throw(
                    RaidenUnrecoverableError(
                        f"A greenlet used the CPU for longer than "
                        f"{gevent.config.max_blocking_time} seconds, killing it"
                    )
                )
            )

    monitor_thread.add_monitoring_function(kill_offender, gevent.config.max_blocking_time)
