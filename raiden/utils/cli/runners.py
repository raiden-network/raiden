import signal
import sys
import textwrap
import traceback
from datetime import datetime
from tempfile import NamedTemporaryFile
from typing import Any, Dict

import click
import gevent
import gevent.monkey
import structlog
from gevent.event import AsyncResult
from requests.exceptions import ConnectionError as RequestsConnectionError

from raiden.api.rest import APIServer, RestAPI
from raiden.exceptions import (
    APIServerPortInUseError,
    EthNodeCommunicationError,
    RaidenError,
    RaidenServicePortInUseError,
    ReplacementTransactionUnderpriced,
    TransactionAlreadyPending,
)
from raiden.log_config import configure_logging
from raiden.network.sockfactory import SocketFactory
from raiden.settings import DEFAULT_SHUTDOWN_TIMEOUT
from raiden.tasks import check_gas_reserve, check_version
from raiden.utils import get_system_spec, split_endpoint, typing
from raiden.utils.echo_node import EchoNode
from raiden.utils.runnable import Runnable

from .app import run_app

log = structlog.get_logger(__name__)


ETHEREUM_NODE_COMMUNICATION_ERROR = (
    '\n'
    'Could not contact the ethereum node through JSON-RPC.\n'
    'Please make sure that JSON-RPC is enabled for these interfaces:\n'
    '\n'
    '    eth_*, net_*, web3_*\n'
    '\n'
    'geth: https://github.com/ethereum/go-ethereum/wiki/Management-APIs\n'
)


class NodeRunner:
    def __init__(self, options: Dict[str, Any], ctx):
        self._options = options
        self._ctx = ctx
        self._raiden_api = None

    @property
    def _welcome_string(self):
        return f"Welcome to Raiden, version {get_system_spec()['raiden']}!"

    def _startup_hook(self):
        """ Hook that is called after startup is finished. Intended for subclass usage. """
        pass

    def _shutdown_hook(self):
        """ Hook that is called just before shutdown. Intended for subclass usage. """
        pass

    def run(self):
        click.secho(self._welcome_string, fg='green')
        click.secho(
            textwrap.dedent(
                '''\
                ----------------------------------------------------------------------
                | This is an Alpha version of experimental open source software      |
                | released under the MIT license and may contain errors and/or bugs. |
                | Use of the software is at your own risk and discretion. No         |
                | guarantee whatsoever is made regarding its suitability for your    |
                | intended purposes and its compliance with applicable law and       |
                | regulations. It is up to the user to determine the software´s      |
                | quality and suitability and whether its use is compliant with its  |
                | respective regulatory regime.                                      |
                |                                                                    |
                | Privacy notice: Please be aware, that by using the Raiden Client,  |
                | your Ethereum address, channels, channel deposits, settlements and |
                | the Ethereum address of your settlement counterparty will be       |
                | stored on the Ethereum chain, i.e. on servers of Ethereum node     |
                | operators and ergo made publicly available. The same will also be  |
                | stored on systems of parties running other Raiden nodes connected  |
                | to the same token network.                                         |
                |                                                                    |
                | Also be aware, that data on individual Raiden token transfers will |
                | be made available via the Matrix protocol to the recipient,        |
                | intermediating nodes of a specific transfer as well as to the      |
                | Matrix server operators.                                           |
                ----------------------------------------------------------------------''',
            ),
            fg='yellow',
        )
        if not self._options['accept_disclaimer']:
            click.confirm('\nHave you read and acknowledged the above disclaimer?', abort=True)

        configure_logging(
            self._options['log_config'],
            log_json=self._options['log_json'],
            log_file=self._options['log_file'],
            disable_debug_logfile=self._options['disable_debug_logfile'],
        )

        if self._options['config_file']:
            log.debug('Using config file', config_file=self._options['config_file'])

        # TODO:
        # - Ask for confirmation to quit if there are any locked transfers that did
        # not timeout.
        try:
            if self._options['transport'] == 'udp':
                (listen_host, listen_port) = split_endpoint(self._options['listen_address'])
                try:
                    with SocketFactory(
                        listen_host, listen_port, strategy=self._options['nat'],
                    ) as mapped_socket:
                        self._options['mapped_socket'] = mapped_socket
                        app = self._run_app()

                except RaidenServicePortInUseError:
                    click.secho(
                        'ERROR: Address %s:%s is in use. '
                        'Use --listen-address <host:port> to specify port to listen on.' %
                        (listen_host, listen_port),
                        fg='red',
                    )
                    sys.exit(1)
            elif self._options['transport'] == 'matrix':
                self._options['mapped_socket'] = None
                app = self._run_app()
            else:
                # Shouldn't happen
                raise RuntimeError(f"Invalid transport type '{self._options['transport']}'")
            app.stop()
        except (ReplacementTransactionUnderpriced, TransactionAlreadyPending) as e:
            click.secho(
                '{}. Please make sure that this Raiden node is the '
                'only user of the selected account'.format(str(e)),
                fg='red',
            )
            sys.exit(1)

    def _run_app(self):
        from raiden.ui.console import Console
        from raiden.api.python import RaidenAPI

        # this catches exceptions raised when waiting for the stalecheck to complete
        try:
            app_ = run_app(**self._options)
        except (EthNodeCommunicationError, RequestsConnectionError):
            print(ETHEREUM_NODE_COMMUNICATION_ERROR)
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
        if version is not None:
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
                app_.config.get('shutdown_timeout', DEFAULT_SHUTDOWN_TIMEOUT),
                raise_error=True,
            )

        return app_


class EchoNodeRunner(NodeRunner):
    def __init__(self, options: Dict[str, Any], ctx, token_address: typing.TokenAddress):
        super().__init__(options, ctx)
        self._token_address = token_address
        self._echo_node = None

    @property
    def _welcome_string(self):
        return '{} [ECHO NODE]'.format(super(EchoNodeRunner, self)._welcome_string)

    def _startup_hook(self):
        self._echo_node = EchoNode(self._raiden_api, self._token_address)

    def _shutdown_hook(self):
        self._echo_node.stop()
