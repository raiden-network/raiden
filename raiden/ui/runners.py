import signal
from typing import Any, Dict, List, Optional

import gevent
import gevent.monkey
import structlog
from click import Context
from gevent.event import AsyncResult

from raiden import constants, settings
from raiden.api.python import RaidenAPI
from raiden.api.rest import APIServer, RestAPI
from raiden.log_config import configure_logging
from raiden.raiden_service import RaidenService
from raiden.tasks import check_gas_reserve, check_network_id, check_rdn_deposits, check_version
from raiden.utils.debugging import limit_thread_cpu_usage_by_time
from raiden.utils.echo_node import EchoNode
from raiden.utils.http import split_endpoint
from raiden.utils.runnable import Runnable
from raiden.utils.system import get_system_spec
from raiden.utils.typing import Port, TokenAddress

from ..utils.gevent import spawn_named
from .app import run_app
from .config import dump_cmd_options, dump_module

log = structlog.get_logger(__name__)
DOC_URL = "http://raiden-network.readthedocs.io/en/stable/rest_api.html"


class NodeRunner:
    def __init__(self, options: Dict[str, Any], ctx: Context) -> None:
        self._options = options
        self._ctx = ctx
        self.raiden_api: Optional[RaidenAPI] = None

    @property
    def welcome_string(self) -> str:
        return f"Welcome to Raiden, version {get_system_spec()['raiden']}!"

    def _startup_hook(self) -> None:
        """ Hook that is called after startup is finished. Intended for subclass usage. """
        pass

    def _shutdown_hook(self) -> None:
        """ Hook that is called just before shutdown. Intended for subclass usage. """
        pass

    def run(self) -> None:
        configure_logging(
            self._options["log_config"],
            log_json=self._options["log_json"],
            log_file=self._options["log_file"],
            disable_debug_logfile=self._options["disable_debug_logfile"],
            debug_log_file_path=self._options["debug_logfile_path"],
        )

        log.info("Starting Raiden", **get_system_spec())

        if self._options["config_file"]:
            log.debug("Using config file", config_file=self._options["config_file"])

    def _start_services(self) -> None:
        if self._options["showconfig"]:
            print("Configuration Dump:")
            dump_cmd_options(self._options)
            dump_module("settings", settings)
            dump_module("constants", constants)

        app = run_app(**self._options)

        gevent_tasks: List[gevent.Greenlet] = list()
        runnable_tasks: List[Runnable] = list()

        runnable_tasks.append(app.raiden)

        domain_list = []
        if self._options["rpccorsdomain"]:
            if "," in self._options["rpccorsdomain"]:
                for domain in self._options["rpccorsdomain"].split(","):
                    domain_list.append(str(domain))
            else:
                domain_list.append(str(self._options["rpccorsdomain"]))

        self.raiden_api = RaidenAPI(app.raiden)

        if self._options["rpc"]:
            rest_api = RestAPI(self.raiden_api)
            (api_host, api_port) = split_endpoint(self._options["api_address"])

            if not api_port:
                api_port = Port(settings.DEFAULT_HTTP_SERVER_PORT)

            api_server = APIServer(
                rest_api,
                config={"host": api_host, "port": api_port},
                cors_domain_list=domain_list,
                web_ui=self._options["web_ui"],
                eth_rpc_endpoint=self._options["eth_rpc_endpoint"],
            )
            api_server.start()

            url = f"http://{api_host}:{api_port}/"
            print(
                f"The Raiden API RPC server is now running at {url}.\n\n See "
                f"the Raiden documentation for all available endpoints at\n "
                f"{DOC_URL}"
            )
            runnable_tasks.append(api_server)

        if self._options["console"]:
            from raiden.ui.console import Console

            console = Console(app)
            console.start()

            gevent_tasks.append(console)

        gevent_tasks.append(
            spawn_named("check_version", check_version, get_system_spec()["raiden"])
        )
        gevent_tasks.append(spawn_named("check_gas_reserve", check_gas_reserve, app.raiden))
        gevent_tasks.append(
            spawn_named(
                "check_network_id",
                check_network_id,
                app.raiden.rpc_client.chain_id,
                app.raiden.rpc_client.web3,
            )
        )

        spawn_user_deposit_task = app.user_deposit and (
            self._options["pathfinding_service_address"] or self._options["enable_monitoring"]
        )
        if spawn_user_deposit_task:
            gevent_tasks.append(
                spawn_named("check_rdn_deposits", check_rdn_deposits, app.raiden, app.user_deposit)
            )

        self._startup_hook()

        stop_event: AsyncResult[None] = AsyncResult()

        def sig_set(sig: Any = None, _frame: Any = None) -> None:
            stop_event.set(sig)

        gevent.signal(signal.SIGQUIT, sig_set)
        gevent.signal(signal.SIGTERM, sig_set)
        gevent.signal(signal.SIGINT, sig_set)

        # Make sure RaidenService is the last service in the list.
        runnable_tasks.reverse()

        # quit if any task exits, successfully or not
        for runnable in runnable_tasks:
            runnable.greenlet.link(stop_event)

        for task in gevent_tasks:
            task.link(stop_event)

        msg = (
            "The RaidenService must be last service to stop, since the other "
            "services depend on it to run. Without this it is not possible to have a "
            "clean shutdown, e.g. the RestAPI must be stopped before "
            "RaidenService, otherwise it is possible for a request to be "
            "processed after the RaidenService was stopped and it will cause a "
            "crash."
        )
        assert isinstance(runnable_tasks[-1], RaidenService), msg

        try:
            # Only enable the cpu limit after initialization has finished,
            # since there wil be long running tasks during startup, which are
            # not a problem for normal operation.
            if self._options["environment_type"] == constants.Environment.DEVELOPMENT:
                limit_thread_cpu_usage_by_time()

            stop_event.get()
            print("Signal received. Shutting down ...")
        finally:
            self._shutdown_hook()

            for task in gevent_tasks:
                task.kill()

            for task in runnable_tasks:
                task.stop()

            gevent.joinall(
                set(gevent_tasks + runnable_tasks), app.config.shutdown_timeout, raise_error=True
            )

            app.stop()


class MatrixRunner(NodeRunner):
    def run(self) -> None:
        super().run()
        self._start_services()


class EchoNodeRunner(NodeRunner):
    def __init__(self, options: Dict[str, Any], ctx: Context, token_address: TokenAddress) -> None:
        super().__init__(options, ctx)
        self._token_address = token_address
        self._echo_node: Optional[EchoNode] = None

    def run(self) -> None:
        super().run()
        self._start_services()

    @property
    def welcome_string(self) -> str:
        return "{} [ECHO NODE]".format(super().welcome_string)

    def _startup_hook(self) -> None:
        if self.raiden_api is not None:
            self._echo_node = EchoNode(self.raiden_api, self._token_address)

    def _shutdown_hook(self) -> None:
        if self._echo_node:
            self._echo_node.stop()
