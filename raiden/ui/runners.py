import signal
import sys
import traceback
from copy import deepcopy
from datetime import datetime
from tempfile import NamedTemporaryFile
from typing import Any, Dict

import click
import gevent
import gevent.monkey
import structlog
from gevent.event import AsyncResult
from requests.exceptions import ConnectionError as RequestsConnectionError

from raiden import constants, settings
from raiden.api.rest import APIServer, RestAPI
from raiden.app import App
from raiden.exceptions import (
    APIServerPortInUseError,
    EthNodeCommunicationError,
    EthNodeInterfaceError,
    RaidenError,
    RaidenServicePortInUseError,
)
from raiden.log_config import configure_logging
from raiden.network.sockfactory import SocketFactory
from raiden.tasks import check_gas_reserve, check_version
from raiden.utils import get_system_spec, merge_dict, split_endpoint, typing
from raiden.utils.echo_node import EchoNode
from raiden.utils.runnable import Runnable

from .app import run_app
from .config import dump_cmd_options, dump_config, dump_module

log = structlog.get_logger(__name__)


ETHEREUM_NODE_COMMUNICATION_ERROR = (
    '\n'
    'Could not contact the ethereum node through JSON-RPC.\n'
    'Please make sure that the ethereum node is running and JSON-RPC is enabled.'
)


class NodeRunner:
    def __init__(self, options: Dict[str, Any], ctx):
        self._options = options
        self._ctx = ctx
        self._raiden_api = None

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
            self._options['log_config'],
            log_json=self._options['log_json'],
            log_file=self._options['log_file'],
            disable_debug_logfile=self._options['disable_debug_logfile'],
        )

        log.info('Starting Raiden', **get_system_spec())

        if self._options['config_file']:
            log.debug('Using config file', config_file=self._options['config_file'])

    def _start_services(self):
        from raiden.ui.console import Console
        from raiden.api.python import RaidenAPI

        config = deepcopy(App.DEFAULT_CONFIG)
        if self._options.get('extra_config', dict()):
            merge_dict(config, self._options['extra_config'])
            del self._options['extra_config']
        self._options['config'] = config

        if self._options['showconfig']:
            print('Configuration Dump:')
            dump_config(config)
            dump_cmd_options(self._options)
            dump_module('settings', settings)
            dump_module('constants', constants)

        # this catches exceptions raised when waiting for the stalecheck to complete
        try:
            app_ = run_app(**self._options)
        except (EthNodeCommunicationError, RequestsConnectionError):
            print(ETHEREUM_NODE_COMMUNICATION_ERROR)
            sys.exit(1)
        except RuntimeError as e:
            click.secho(str(e), fg='red')
            sys.exit(1)
        except EthNodeInterfaceError as e:
            click.secho(str(e), fg='red')
            sys.exit(1)

        tasks = [app_.raiden]  # RaidenService takes care of Transport and AlarmTask

        domain_list = []
        if self._options['rpccorsdomain']:
            if ',' in self._options['rpccorsdomain']:
                for domain in self._options['rpccorsdomain'].split(','):
                    domain_list.append(str(domain))
            else:
                domain_list.append(str(self._options['rpccorsdomain']))

        self._raiden_api = RaidenAPI(app_.raiden)

        if self._options['rpc']:
            rest_api = RestAPI(self._raiden_api)
            api_server = APIServer(
                rest_api,
                cors_domain_list=domain_list,
                web_ui=self._options['web_ui'],
                eth_rpc_endpoint=self._options['eth_rpc_endpoint'],
            )
            (api_host, api_port) = split_endpoint(self._options['api_address'])

            try:
                api_server.start(api_host, api_port)
            except APIServerPortInUseError:
                click.secho(
                    f'ERROR: API Address {api_host}:{api_port} is in use. '
                    f'Use --api-address <host:port> to specify a different port.',
                    fg='red',
                )
                sys.exit(1)

            print(
                'The Raiden API RPC server is now running at http://{}:{}/.\n\n'
                'See the Raiden documentation for all available endpoints at\n'
                'http://raiden-network.readthedocs.io/en/stable/rest_api.html'.format(
                    api_host,
                    api_port,
                ),
            )
            tasks.append(api_server)

        if self._options['console']:
            console = Console(app_)
            console.start()
            tasks.append(console)

        # spawn a greenlet to handle the version checking
        version = get_system_spec()['raiden']
        tasks.append(gevent.spawn(check_version, version))

        # spawn a greenlet to handle the gas reserve check
        tasks.append(gevent.spawn(check_gas_reserve, app_.raiden))

        self._startup_hook()

        # wait for interrupt
        event = AsyncResult()

        def sig_set(sig=None, _frame=None):
            event.set(sig)

        gevent.signal(signal.SIGQUIT, sig_set)
        gevent.signal(signal.SIGTERM, sig_set)
        gevent.signal(signal.SIGINT, sig_set)

        # quit if any task exits, successfully or not
        for task in tasks:
            task.link(event)

        try:
            event.get()
            print('Signal received. Shutting down ...')
        except (EthNodeCommunicationError, RequestsConnectionError):
            print(ETHEREUM_NODE_COMMUNICATION_ERROR)
            sys.exit(1)
        except RaidenError as ex:
            click.secho(f'FATAL: {ex}', fg='red')
        except Exception as ex:
            with NamedTemporaryFile(
                'w',
                prefix=f'raiden-exception-{datetime.utcnow():%Y-%m-%dT%H-%M}',
                suffix='.txt',
                delete=False,
            ) as traceback_file:
                traceback.print_exc(file=traceback_file)
                click.secho(
                    f'FATAL: An unexpected exception occured. '
                    f'A traceback has been written to {traceback_file.name}\n'
                    f'{ex}',
                    fg='red',
                )
        finally:
            self._shutdown_hook()

            def stop_task(task):
                try:
                    if isinstance(task, Runnable):
                        task.stop()
                    else:
                        task.kill()
                finally:
                    task.get()  # re-raise

            gevent.joinall(
                [gevent.spawn(stop_task, task) for task in tasks],
                app_.config.get('shutdown_timeout', settings.DEFAULT_SHUTDOWN_TIMEOUT),
                raise_error=True,
            )

        return app_


class UDPRunner(NodeRunner):
    def run(self):
        super().run()

        (listen_host, listen_port) = split_endpoint(self._options['listen_address'])
        try:
            with SocketFactory(
                listen_host, listen_port, strategy=self._options['nat'],
            ) as mapped_socket:
                self._options['mapped_socket'] = mapped_socket
                app = self._start_services()

        except RaidenServicePortInUseError:
            click.secho(
                'ERROR: Address %s:%s is in use. '
                'Use --listen-address <host:port> to specify port to listen on.' %
                (listen_host, listen_port),
                fg='red',
            )
            sys.exit(1)
        return app


class MatrixRunner(NodeRunner):
    def run(self):
        super().run()
        self._options['mapped_socket'] = None
        return self._start_services()


class EchoNodeRunner(NodeRunner):
    def __init__(self, options: Dict[str, Any], ctx, token_address: typing.TokenAddress):
        super().__init__(options, ctx)
        self._token_address = token_address
        self._echo_node = None

    @property
    def welcome_string(self):
        return '{} [ECHO NODE]'.format(super().welcome_string)

    def _startup_hook(self):
        self._echo_node = EchoNode(self._raiden_api, self._token_address)

    def _shutdown_hook(self):
        self._echo_node.stop()
