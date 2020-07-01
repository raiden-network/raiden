import signal
from typing import Any, Dict, List, Optional

import gevent
import gevent.monkey
import structlog
from gevent.event import AsyncResult

from raiden.tasks import check_gas_reserve, check_network_id, check_rdn_deposits, check_version
from raiden.ui.app import run_app
from raiden.utils.gevent import spawn_named
from raiden.utils.system import get_system_spec

log = structlog.get_logger(__name__)


def run_services(options: Dict[str, Any]) -> None:
    if options["config_file"]:
        log.debug("Using config file", config_file=options["config_file"])

    app = run_app(**options)

    gevent_tasks: List[gevent.Greenlet] = list()

    if options["console"]:
        from raiden.ui.console import Console

        console = Console(app)
        console.start()

        gevent_tasks.append(console)

    gevent_tasks.append(spawn_named("check_version", check_version, get_system_spec()["raiden"]))
    gevent_tasks.append(spawn_named("check_gas_reserve", check_gas_reserve, app.raiden))
    gevent_tasks.append(
        spawn_named(
            "check_network_id",
            check_network_id,
            app.raiden.rpc_client.chain_id,
            app.raiden.rpc_client.web3,
        )
    )

    spawn_user_deposit_task = app.raiden.default_user_deposit and (
        options["pathfinding_service_address"] or options["enable_monitoring"]
    )
    if spawn_user_deposit_task:
        gevent_tasks.append(
            spawn_named(
                "check_rdn_deposits",
                check_rdn_deposits,
                app.raiden,
                app.raiden.default_user_deposit,
            )
        )

    stop_event: AsyncResult[Optional[signal.Signals]]  # pylint: disable=no-member
    stop_event = AsyncResult()

    def sig_set(sig: int, _frame: Any = None) -> None:
        stop_event.set(signal.Signals(sig))  # pylint: disable=no-member

    gevent.signal.signal(signal.SIGQUIT, sig_set)  # pylint: disable=no-member
    gevent.signal.signal(signal.SIGTERM, sig_set)  # pylint: disable=no-member
    gevent.signal.signal(signal.SIGINT, sig_set)  # pylint: disable=no-member

    # The SIGPIPE handler should not be installed. It is handled by the python
    # runtime, and an exception will be raised at the call site that triggered
    # the error.
    #
    # The default SIGPIPE handler set by the libc will terminate the process
    # [4]. However, the CPython interpreter changes the handler to IGN [3].
    # This allows for error reporting by the system calls that write to files.
    # Because of this, calling `send` to a closed socket will return an `EPIPE`
    # error [2], the error is then converted to an exception [5,6].
    #
    # 1 - https://github.com/python/cpython/blob/3.8/Modules/socketmodule.c#L4088
    # 2 - http://man7.org/linux/man-pages/man2/send.2.html
    # 3 - https://github.com/python/cpython/blob/3.8/Python/pylifecycle.c#L2306-L2307
    # 4 - https://www.gnu.org/software/libc/manual/html_node/Operation-Error-Signals.html
    # 5 - https://github.com/python/cpython/blob/3.8/Modules/socketmodule.c#L836-L838
    # 6 - https://github.com/python/cpython/blob/3.8/Modules/socketmodule.c#L627-L628
    # 7 - https://docs.python.org/3/library/signal.html#note-on-sigpipe
    #
    # gevent.signal.signal(signal.SIGPIPE, sig_set)  # pylint: disable=no-member

    # quit if any task exits, successfully or not
    app.raiden.greenlet.link(stop_event)
    for task in gevent_tasks:
        task.link(stop_event)

    try:
        signal_received = stop_event.get()
        if signal_received:
            print("\r", end="")  # Reset cursor to overwrite a possibly printed "^C"
            log.info("Signal received. Shutting down.", signal=signal_received)
    finally:
        for task in gevent_tasks:
            task.kill()

        app.raiden.stop()

        gevent.joinall(
            set(gevent_tasks + [app.raiden]), app.config.shutdown_timeout, raise_error=True
        )

        app.stop()
