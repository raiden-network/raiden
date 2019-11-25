from typing import Any


def enable_gevent_monitoring_signal() -> None:
    """ Install a signal handler for SIGUSR1 that executes gevent.util.print_run_info().
    This can help evaluating the gevent greenlet tree.
    See http://www.gevent.org/monitoring.html for more information.

    Usage:
        pytest [...]
        # while test is running (or stopped in a pdb session):
        kill -SIGUSR1 $(pidof -x pytest)
    """
    import gevent.util
    import signal

    def on_signal(signalnum: Any, stack_frame: Any) -> None:  # pylint: disable=unused-argument
        gevent.util.print_run_info()

    signal.signal(signal.SIGUSR1, on_signal)
