import json
import os
import sys
import textwrap
import traceback
from copy import deepcopy
from pathlib import Path
from subprocess import DEVNULL
from tempfile import mktemp
from urllib.parse import urljoin

import click
import structlog
from eth_utils import to_canonical_address, to_checksum_address
from mirakuru import ProcessExitedWithError

from raiden.api.rest import APIServer, RestAPI
from raiden.app import App
from raiden.constants import Environment
from raiden.exceptions import ReplacementTransactionUnderpriced, TransactionAlreadyPending
from raiden.log_config import configure_logging
from raiden.network.sockfactory import SocketFactory
from raiden.network.utils import get_free_port
from raiden.settings import INITIAL_PORT
from raiden.utils import get_system_spec, merge_dict, split_endpoint
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    EnvironmentChoiceType,
    GasPriceChoiceType,
    MatrixServerType,
    NATChoiceType,
    NetworkChoiceType,
    PathRelativePath,
    apply_config_file,
    group,
    option,
    option_group,
)
from raiden.utils.http import HTTPExecutor
from raiden_contracts.constants import CONTRACT_ENDPOINT_REGISTRY, CONTRACT_TOKEN_NETWORK_REGISTRY

from .app import run_app
from .runners import EchoNodeRunner, MatrixRunner, UDPRunner

log = structlog.get_logger(__name__)


def options(func):
    """Having the common app options as a decorator facilitates reuse."""

    # Until https://github.com/pallets/click/issues/926 is fixed the options need to be re-defined
    # for every use
    options_ = [
        option(
            '--datadir',
            help='Directory for storing raiden data.',
            default=os.path.join(os.path.expanduser('~'), '.raiden'),
            type=click.Path(
                exists=False,
                dir_okay=True,
                file_okay=False,
                writable=True,
                resolve_path=True,
                allow_dash=False,
            ),
            show_default=True,
        ),
        option(
            '--config-file',
            help='Configuration file (TOML)',
            default=os.path.join('${datadir}', 'config.toml'),
            type=PathRelativePath(
                file_okay=True,
                dir_okay=False,
                exists=False,
                readable=True,
                resolve_path=True,
            ),
            show_default=True,
        ),
        option(
            '--keystore-path',
            help=(
                'If you have a non-standard path for the ethereum keystore directory'
                ' provide it using this argument.'
            ),
            default=None,
            type=click.Path(exists=True),
            show_default=True,
        ),
        option(
            '--address',
            help=(
                'The ethereum address you would like raiden to use and for which '
                'a keystore file exists in your local system.'
            ),
            default=None,
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--password-file',
            help='Text file containing the password for the provided account',
            default=None,
            type=click.File(lazy=True),
            show_default=True,
        ),
        option(
            '--tokennetwork-registry-contract-address',
            help='hex encoded address of the Token Network Registry contract.',
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--secret-registry-contract-address',
            help='hex encoded address of the Secret Registry contract.',
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--endpoint-registry-contract-address',
            help='hex encoded address of the Endpoint Registry contract.',
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            '--console',
            help='Start the interactive raiden console',
            is_flag=True,
        ),
        option(
            '--transport',
            help='Transport system to use. Matrix is experimental.',
            type=click.Choice(['udp', 'matrix']),
            default='matrix',
            show_default=True,
        ),
        option(
            '--network-id',
            help=(
                'Specify the network name/id of the Ethereum network to run Raiden on.\n'
                'Available networks:\n'
                '"mainnet" - network id: 1\n'
                '"ropsten" - network id: 3\n'
                '"rinkeby" - network id: 4\n'
                '"kovan" - network id: 42\n'
                '"<NETWORK_ID>": use the given network id directly\n'
            ),
            type=NetworkChoiceType(['mainnet', 'ropsten', 'rinkeby', 'kovan', '<NETWORK_ID>']),
            default='kovan',
            show_default=True,
        ),
        option(
            '--environment-type',
            help=(
                'Specify the environment (production or development).\n'
                'The "production" setting adds some safety measures and is mainly intended '
                'for running Raiden on the mainnet.\n'
            ),
            type=EnvironmentChoiceType([e.value for e in Environment]),
            default=Environment.PRODUCTION.value,
            show_default=True,
        ),
        option(
            '--accept-disclaimer',
            help='Bypass the experimental software disclaimer prompt',
            is_flag=True,
        ),
        option(
            '--showconfig',
            help='Show all configuration values used to control Raiden\'s behavior',
            is_flag=True,
        ),
        option_group(
            'Ethereum Node Options',
            option(
                '--sync-check/--no-sync-check',
                help='Checks if the ethereum node is synchronized against etherscan.',
                default=True,
                show_default=True,
            ),
            option(
                '--gas-price',
                help=(
                    'Set the gas price for ethereum transactions. If not provided '
                    'the normal gas price startegy is used.\n'
                    'Available options:\n'
                    '"fast" - transactions are usually mined within 60 seconds\n'
                    '"normal" - transactions are usually mined within 5 minutes\n'
                    '<GAS_PRICE> - use given gas price\n'
                ),
                type=GasPriceChoiceType(['normal', 'fast']),
                default='fast',
                show_default=True,
            ),
            option(
                '--eth-rpc-endpoint',
                help=(
                    '"host:port" address of ethereum JSON-RPC server.\n'
                    'Also accepts a protocol prefix (http:// or https://) with optional port'
                ),
                default='http://127.0.0.1:8545',  # geth default jsonrpc port
                type=str,
                show_default=True,
            ),
        ),
        option_group(
            'UDP Transport Options',
            option(
                '--listen-address',
                help='"host:port" for the raiden service to listen on.',
                default='0.0.0.0:{}'.format(INITIAL_PORT),
                type=str,
                show_default=True,
            ),
            option(
                '--max-unresponsive-time',
                help=(
                    'Max time in seconds for which an address can send no packets and '
                    'still be considered healthy.'
                ),
                default=30,
                type=int,
                show_default=True,
            ),
            option(
                '--send-ping-time',
                help=(
                    'Time in seconds after which if we have received no message from a '
                    'node we have a connection with, we are going to send a PING message'
                ),
                default=60,
                type=int,
                show_default=True,
            ),
            option(
                '--nat',
                help=(
                    'Manually specify method to use for determining public IP / NAT traversal.\n'
                    'Available methods:\n'
                    '"auto" - Try UPnP, then STUN, fallback to none\n'
                    '"upnp" - Try UPnP, fallback to none\n'
                    '"stun" - Try STUN, fallback to none\n'
                    '"none" - Use the local interface address '
                    '(this will likely cause connectivity issues)\n'
                    '"ext:<IP>[:<PORT>]" - manually specify the external IP (and optionally port '
                    'number)'
                ),
                type=NATChoiceType(['auto', 'upnp', 'stun', 'none', 'ext:<IP>[:<PORT>]']),
                default='auto',
                show_default=True,
                option_group='udp_transport',
            ),
        ),
        option_group(
            'Matrix Transport Options',
            option(
                '--matrix-server',
                help=(
                    'Matrix homeserver to use for communication.\n'
                    'Valid values:\n'
                    '"auto" - automatically select a suitable homeserver\n'
                    'A URL pointing to a Raiden matrix homeserver'
                ),
                default='auto',
                type=MatrixServerType(['auto', '<url>']),
                show_default=True,
            ),
        ),
        option_group(
            'Logging Options',
            option(
                '--log-config',
                help='Log level configuration.\n'
                     'Format: [<logger-name-1>]:<level>[,<logger-name-2>:level][,...]',
                type=LOG_LEVEL_CONFIG_TYPE,
                default=':info',
                show_default=True,
            ),
            option(
                '--log-file',
                help='file path for logging to file',
                default=None,
                type=str,
                show_default=True,
            ),
            option(
                '--log-json',
                help='Output log lines in JSON format',
                is_flag=True,
            ),
            option(
                '--disable-debug-logfile',
                help=(
                    'Disable the debug logfile feature. This is independent of '
                    'the normal logging setup'
                ),
                is_flag=True,
            ),
        ),
        option_group(
            'RPC Options',
            option(
                '--rpc/--no-rpc',
                help='Start with or without the RPC server.',
                default=True,
                show_default=True,
            ),
            option(
                '--rpccorsdomain',
                help='Comma separated list of domains to accept cross origin requests.',
                default='http://localhost:*/*',
                type=str,
                show_default=True,
            ),
            option(
                '--api-address',
                help='"host:port" for the RPC server to listen on.',
                default='127.0.0.1:5001',
                type=str,
                show_default=True,
            ),
            option(
                '--web-ui/--no-web-ui',
                help=(
                    'Start with or without the web interface. Requires --rpc. '
                    'It will be accessible at http://<api-address>. '
                ),
                default=True,
                show_default=True,
            ),
        ),
        option_group(
            'Debugging options',
            option(
                '--unrecoverable-error-should-crash',
                help=(
                    'DO NOT use, unless you know what you are doing. If provided '
                    'along with a production environment setting then all '
                    'unrecoverable errors will lead to a crash and not simply get logged.'
                ),
                is_flag=True,
                default=False,
            ),
        ),
    ]

    for option_ in reversed(options_):
        func = option_(func)
    return func


@group(invoke_without_command=True, context_settings={'max_content_width': 120})
@options
@click.pass_context
def run(ctx, **kwargs):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if kwargs['config_file']:
        apply_config_file(run, kwargs, ctx)

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    runner = None
    if kwargs['transport'] == 'udp':
        runner = UDPRunner(kwargs, ctx)
    elif kwargs['transport'] == 'matrix':
        runner = MatrixRunner(kwargs, ctx)
    else:
        # Shouldn't happen
        raise RuntimeError(f"Invalid transport type '{kwargs['transport']}'")

    click.secho(runner.welcome_string, fg='green')
    click.secho(
        textwrap.dedent(
            '''\
            ----------------------------------------------------------------------
            | This is an Alpha version of experimental open source software      |
            | released as a test version under an MIT license and may contain    |
            | errors and/or bugs. No guarantee or representations whatsoever is  |
            | made regarding its suitability (or its use) for any purpose or     |
            | regarding its compliance with any applicable laws and regulations. |
            | Use of the software is at your own risk and discretion and by      |
            | using the software you acknowledge that you have read this         |
            | disclaimer, understand its contents, assume all risk related       |
            | thereto and hereby release, waive, discharge and covenant not to   |
            | sue Brainbot Labs Establishment or any officers, employees or      |
            | affiliates from and for any direct or indirect liability resulting |
            | from the use of the software as permissible by applicable laws and |
            | regulations.                                                       |
            |                                                                    |
            | Privacy Warning: Please be aware, that by using the Raiden Client, |
            | among others, your Ethereum address, channels, channel deposits,   |
            | settlements and the Ethereum address of your channel counterparty  |
            | will be stored on the Ethereum chain, i.e. on servers of Ethereum  |
            | node operators and ergo are to a certain extent publicly available.|
            | The same might also be stored on systems of parties running Raiden |
            | nodes connected to the same token network. Data present in the     |
            | Ethereum chain is very unlikely to be able to be changed, removed  |
            | or deleted from the public arena.                                  |
            |                                                                    |
            | Also be aware, that data on individual Raiden token transfers will |
            | be made available via the Matrix protocol to the recipient,        |
            | intermediating nodes of a specific transfer as well as to the      |
            | Matrix server operators.                                           |
            ----------------------------------------------------------------------''',
        ),
        fg='yellow',
    )
    if not kwargs['accept_disclaimer']:
        click.confirm(
            '\nHave you read, understood and hereby accept the above '
            'disclaimer and privacy warning?',
            abort=True,
        )

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.
    try:
        app = runner.run()
        app.stop()
    except (ReplacementTransactionUnderpriced, TransactionAlreadyPending) as e:
        click.secho(
            '{}. Please make sure that this Raiden node is the '
            'only user of the selected account'.format(str(e)),
            fg='red',
        )
        sys.exit(1)


@run.command()
@option(
    '--short',
    is_flag=True,
    help='Only display Raiden version',
)
def version(short, **kwargs):  # pylint: disable=unused-argument
    """Print version information and exit. """
    if short:
        print(get_system_spec()['raiden'])
    else:
        print(json.dumps(
            get_system_spec(),
            indent=2,
        ))


@run.command()
@option(
    '--debug',
    is_flag=True,
    help='Drop into pdb on errors.',
)
@option(
    '--local-matrix',
    help='Command-line to be used to run a local matrix server (or "none")',
    default=str(Path(__file__).parent.parent.parent.joinpath('.synapse', 'run_synapse.sh')),
    show_default=True,
)
@click.pass_context
def smoketest(ctx, debug, local_matrix, **kwargs):  # pylint: disable=unused-argument
    """ Test, that the raiden installation is sane. """
    from raiden.api.python import RaidenAPI
    from raiden.tests.utils.smoketest import (
        TEST_PARTNER_ADDRESS,
        TEST_DEPOSIT_AMOUNT,
        run_smoketests,
        setup_testchain_and_raiden,
    )

    report_file = mktemp(suffix='.log')
    configure_logging(
        logger_level_config={'': 'DEBUG'},
        log_file=report_file,
        disable_debug_logfile=ctx.parent.params['disable_debug_logfile'],
    )
    click.secho(
        f'Report file: {report_file}',
        fg='yellow',
    )

    def append_report(subject, data):
        with open(report_file, 'a', encoding='UTF-8') as handler:
            handler.write(f'{f" {subject.upper()} ":=^80}{os.linesep}')
            if data is not None:
                if isinstance(data, bytes):
                    data = data.decode()
                handler.writelines([data + os.linesep])

    append_report('Raiden version', json.dumps(get_system_spec()))
    append_report('Raiden log', None)

    step_count = 7
    if ctx.parent.params['transport'] == 'matrix':
        step_count = 8
    step = 0

    def print_step(description, error=False):
        nonlocal step
        step += 1
        click.echo(
            '{} {}'.format(
                click.style(f'[{step}/{step_count}]', fg='blue'),
                click.style(description, fg='green' if not error else 'red'),
            ),
        )

    print_step('Getting smoketest configuration')

    result = setup_testchain_and_raiden(
        ctx.parent.params['transport'],
        ctx.parent.params['matrix_server'],
        print_step,
    )
    args = result['args']
    contract_addresses = result['contract_addresses']
    token = result['token']
    ethereum = result['ethereum']

    for option_ in run.params:
        if option_.name in args.keys():
            args[option_.name] = option_.process_value(ctx, args[option_.name])
        else:
            args[option_.name] = option_.default

    port = next(get_free_port('127.0.0.1', 5001))

    args['api_address'] = 'localhost:' + str(port)

    def _run_smoketest():
        print_step('Starting Raiden')

        config = deepcopy(App.DEFAULT_CONFIG)
        if args.get('extra_config', dict()):
            merge_dict(config, args['extra_config'])
            del args['extra_config']
        args['config'] = config

        # invoke the raiden app
        app = run_app(**args)

        raiden_api = RaidenAPI(app.raiden)
        rest_api = RestAPI(raiden_api)
        api_server = APIServer(rest_api)
        (api_host, api_port) = split_endpoint(args['api_address'])
        api_server.start(api_host, api_port)

        raiden_api.channel_open(
            registry_address=contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            token_address=to_canonical_address(token.contract.address),
            partner_address=to_canonical_address(TEST_PARTNER_ADDRESS),
        )
        raiden_api.set_total_channel_deposit(
            contract_addresses[CONTRACT_TOKEN_NETWORK_REGISTRY],
            to_canonical_address(token.contract.address),
            to_canonical_address(TEST_PARTNER_ADDRESS),
            TEST_DEPOSIT_AMOUNT,
        )
        token_addresses = [to_checksum_address(token.contract.address)]

        success = False
        try:
            print_step('Running smoketest')
            error = run_smoketests(
                app.raiden,
                args['transport'],
                token_addresses,
                contract_addresses[CONTRACT_ENDPOINT_REGISTRY],
                debug=debug,
            )
            if error is not None:
                append_report('Smoketest assertion error', error)
            else:
                success = True
        finally:
            app.stop()
            node = ethereum[0]
            node.send_signal(2)
            err, out = node.communicate()

            append_report('Ethereum stdout', out)
            append_report('Ethereum stderr', err)
        if success:
            print_step(f'Smoketest successful')
        else:
            print_step(f'Smoketest had errors', error=True)
        return success

    if args['transport'] == 'udp':
        with SocketFactory('127.0.0.1', port, strategy='none') as mapped_socket:
            args['mapped_socket'] = mapped_socket
            success = _run_smoketest()
    elif args['transport'] == 'matrix' and local_matrix.lower() != 'none':
        args['mapped_socket'] = None
        print_step('Starting Matrix transport')
        try:
            with HTTPExecutor(
                local_matrix,
                url=urljoin(args['matrix_server'], '/_matrix/client/versions'),
                method='GET',
                io=DEVNULL,
                timeout=30,
                shell=True,
            ):
                args['extra_config'] = {
                    'transport': {
                        'matrix': {
                            'server_name': 'matrix.local.raiden',
                            'available_servers': [],
                        },
                    },
                }
                success = _run_smoketest()
        except (PermissionError, ProcessExitedWithError, FileNotFoundError):
            append_report('Matrix server start exception', traceback.format_exc())
            print_step(
                f'Error during smoketest setup, report was written to {report_file}',
                error=True,
            )
            success = False
    elif args['transport'] == 'matrix' and local_matrix.lower() == "none":
        args['mapped_socket'] = None
        args['extra_config'] = {
            'transport': {
                'matrix': {
                    'server_name': 'matrix.local.raiden',
                    'available_servers': [],
                },
            },
        }
        success = _run_smoketest()
    else:
        # Shouldn't happen
        raise RuntimeError(f"Invalid transport type '{args['transport']}'")

    if not success:
        sys.exit(1)


@run.command(
    help=(
        'Start an echo node.\n'
        'Mainly useful for development.\n'
        'See: https://raiden-network.readthedocs.io/en/stable/api_walkthrough.html'
        '#interacting-with-the-raiden-echo-node'
    ),
)
@click.option('--token-address', type=ADDRESS_TYPE, required=True)
@click.pass_context
def echonode(ctx, token_address):
    """ Start a raiden Echo Node that will send received transfers back to the initiator. """
    EchoNodeRunner(ctx.obj, ctx, token_address).run()
