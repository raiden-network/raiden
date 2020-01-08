import signal
from typing import Any, Dict, List, Optional

import gevent
import gevent.monkey
import structlog
from gevent.event import AsyncResult

from raiden import constants, settings
from raiden.api.python import RaidenAPI
from raiden.api.rest import APIConfig, APIServer, RestAPI, WebUIConfig
from raiden.log_config import configure_logging
from raiden.raiden_service import RaidenService
from raiden.tasks import check_gas_reserve, check_network_id, check_rdn_deposits, check_version
from raiden.utils import typing
from raiden.utils.echo_node import EchoNode
from raiden.utils.http import split_endpoint
from raiden.utils.system import get_system_spec
from raiden.utils.typing import Port

from .app import run_app
from .config import dump_cmd_options, dump_module

log = structlog.get_logger(__name__)
DOC_URL = "http://raiden-network.readthedocs.io/en/stable/rest_api.html"


class NodeRunner:
    def __init__(self, options: Dict[str, Any], ctx):
        self._options = options
        self._ctx = ctx
        self.raiden_api: Optional[RaidenAPI] = None

    @property
    def welcome_string(self):
        return f"Welcome to Raiden, version {get_system_spec()['raiden']}!"

    def _startup_hook(self):
        """ Hook that is called after startup is finished. Intended for subclass usage. """
        pass

    def _shutdown_hook(self):
        """ Hook that is called just before shutdown. Intended for subclass usage. """
        pass

    def run(self):
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

        greenlets: List[gevent.Greenlet] = list()
        stoppables: List[Any] = list()

        greenlets.append(app.raiden.greenlet)
        stoppables.append(app.raiden)

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

            webui_config: Optional[WebUIConfig]
            if self._options["web_ui"]:
                webui_config = WebUIConfig(
                    cors_domain_list=domain_list,
                    eth_rpc_endpoint=self._options["eth_rpc_endpoint"],
                )
            else:
                webui_config = None

            api_server = APIServer(
                rest_api,
                APIConfig(
                    host=api_host, port=api_port, api_prefix="api", webui_config=webui_config
                ),
            )
            greenlets.append(api_server.greenlet)
            stoppables.append(api_server)

            url = f"http://{api_host}:{api_port}/"
            print(
                f"The Raiden API RPC server is now running at {url}.\n\n See "
                f"the Raiden documentation for all available endpoints at\n "
                f"{DOC_URL}"
            )

        if self._options["console"]:
            from raiden.ui.console import Console

            console = Console(app)
            console.start()

            greenlets.append(console)

        greenlets.append(gevent.spawn(check_version, get_system_spec()["raiden"]))
        greenlets.append(gevent.spawn(check_gas_reserve, app.raiden))
        greenlets.append(
            gevent.spawn(
                check_network_id, app.raiden.rpc_client.chain_id, app.raiden.rpc_client.web3
            )
        )

        spawn_user_deposit_task = app.user_deposit and (
            self._options["pathfinding_service_address"] or self._options["enable_monitoring"]
        )
        if spawn_user_deposit_task:
            greenlets.append(gevent.spawn(check_rdn_deposits, app.raiden, app.user_deposit))

        self._startup_hook()

        stop_event: AsyncResult[None] = AsyncResult()

        def sig_set(sig=None, _frame=None):
            stop_event.set(sig)

        gevent.signal(signal.SIGQUIT, sig_set)
        gevent.signal(signal.SIGTERM, sig_set)
        gevent.signal(signal.SIGINT, sig_set)

        # Stop the services in reverse order, this is necessary to make sure
        # the dependencies are only stopped after the running service,
        # otherwise shutdown will fail.
        #
        # Example:
        #
        # - RaidenService is a dependecy for APIServer, therefore the former is
        #   instantiated and added first to the list.
        # - If during shutdown the order is not reversed, the RaidenService
        #   will be stopped before the api, which will lead to errors in the API
        # - To fix the above the order is reversed.
        greenlets.reverse()
        stoppables.reverse()

        # Raiden must stop if any services stops, successfully or not.
        for g in greenlets:
            g.greenlet.link(stop_event)

        msg = (
            "The RaidenService must be last service to stop, since the other "
            "services depend on it to run. Without this it is not possible to have a "
            "clean shutdown, e.g. the RestAPI must be stopped before "
            "RaidenService, otherwise it is possible for a request to be "
            "processed after the RaidenService was stopped and it will cause a "
            "crash."
        )
        assert isinstance(stoppables[-1], RaidenService), msg

        try:
            stop_event.get()
            print("Signal received. Shutting down ...")
        finally:
            self._shutdown_hook()

            for service in stoppables:
                service.stop()

            gevent.joinall(set(stoppables), app.config.shutdown_timeout, raise_error=True)

            for task in greenlets:
                task.kill()

            gevent.joinall(set(greenlets), app.config.shutdown_timeout, raise_error=True)


class MatrixRunner(NodeRunner):
    def run(self):
        super().run()
        return self._start_services()


class EchoNodeRunner(NodeRunner):
    def __init__(self, options: Dict[str, Any], ctx, token_address: typing.TokenAddress):
        super().__init__(options, ctx)
        self._token_address = token_address
        self._echo_node = None

    def run(self):
        super().run()
        return self._start_services()

    @property
    def welcome_string(self):
        return "{} [ECHO NODE]".format(super().welcome_string)

    def _startup_hook(self):
        self._echo_node = EchoNode(self.raiden_api, self._token_address)

    def _shutdown_hook(self):
        self._echo_node.stop()
