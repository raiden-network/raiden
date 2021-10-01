import datetime
import json
import os
import sys
import textwrap
import traceback
from enum import Enum
from importlib.util import find_spec
from io import StringIO
from tempfile import NamedTemporaryFile, mktemp
from typing import Any, AnyStr, Callable, List, Optional

import click
import filelock
import structlog
from jaeger_client import Config
from opentracing.scope_managers.gevent import GeventScopeManager
from requests.exceptions import ConnectionError as RequestsConnectionError, ConnectTimeout
from tornado.ioloop import IOLoop
from urllib3.exceptions import ReadTimeoutError

from raiden.accounts import KeystoreAuthenticationError, KeystoreFileNotFound
from raiden.constants import (
    FLAT_MED_FEE_MIN,
    IMBALANCE_MED_FEE_MAX,
    IMBALANCE_MED_FEE_MIN,
    MATRIX_AUTO_SELECT_SERVER,
    PROPORTIONAL_MED_FEE_MAX,
    PROPORTIONAL_MED_FEE_MIN,
    Environment,
    EthClient,
    RoutingMode,
)
from raiden.exceptions import (
    AddressWithoutCode,
    APIServerPortInUseError,
    ConfigurationError,
    EthereumNonceTooLow,
    EthNodeInterfaceError,
    RaidenUnrecoverableError,
    ReplacementTransactionUnderpriced,
)
from raiden.log_config import configure_logging
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_BLOCKCHAIN_QUERY_INTERVAL,
    DEFAULT_HTTP_SERVER_PORT,
    DEFAULT_PATHFINDING_IOU_TIMEOUT,
    DEFAULT_PATHFINDING_MAX_FEE,
    DEFAULT_PATHFINDING_MAX_PATHS,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
)
from raiden.ui.app import setup_raiden_config
from raiden.ui.runners import run_services
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    ChainChoiceType,
    ConfigParser,
    Context,
    EnumChoiceType,
    ExpandableFile,
    ExpandablePath,
    GasPriceChoiceType,
    MatrixServerType,
    PathRelativePath,
    group,
    option,
    option_group,
)
from raiden.utils.debugging import IDLE, enable_monitoring_signal
from raiden.utils.formatting import to_checksum_address
from raiden.utils.system import get_system_spec
from raiden.utils.tracing import enable_pfs_request_tracing
from raiden.utils.typing import MYPY_ANNOTATION, ChainID
from raiden_contracts.constants import ID_TO_CHAINNAME
from raiden_contracts.contract_manager import ContractDevEnvironment

log = structlog.get_logger(__name__)
ETH_RPC_CONFIG_OPTION = "--eth-rpc-endpoint"
ETH_CHAINID_OPTION = "--network-id"
COMMUNICATION_ERROR = (
    f"\n"
    f"Communicating with an external service failed.\n"
    f"This can be caused by internet connection problems or \n"
    f"any of the following services, Ethereum client or Matrix or pathfinding.\n"
    f"Please try again in five minutes."
    f"\n"
    f"Endpoint used with the Ethereum client: "
    f"'{{}}', this option can be "
    f"configured with the flag {ETH_RPC_CONFIG_OPTION}"
)


class ReturnCode(Enum):
    SUCCESS = 0
    # 1 -> this error code is used arbitraryly in some places, skipping it
    FATAL = 2
    GENERIC_COMMUNICATION_ERROR = 3
    ETH_INTERFACE_ERROR = 4
    PORT_ALREADY_IN_USE = 5
    ETH_ACCOUNT_ERROR = 6
    RAIDEN_CONFIGURATION_ERROR = 7
    SMART_CONTRACTS_CONFIGURATION_ERROR = 8


def windows_not_supported(feature_name: str) -> None:
    if os.name == "nt":
        click.echo(f"{feature_name.title()} not supported on Windows")
        exit(1)


def write_stack_trace(ex: Exception) -> None:
    file = NamedTemporaryFile(
        "w",
        prefix=f"raiden-exception-{datetime.datetime.utcnow():%Y-%m-%dT%H-%M}",
        suffix=".txt",
        delete=False,
    )
    with file as traceback_file:
        traceback.print_exc(file=traceback_file)
        traceback.print_exc()
        click.secho(
            f"FATAL: An unexpected exception occurred. "
            f"A traceback has been written to {traceback_file.name}\n"
            f"{ex}",
            fg="red",
        )


def get_version(short: bool) -> str:
    if short:
        return get_system_spec()["raiden"]
    else:
        return json.dumps(get_system_spec(), indent=2)


def handle_version_option(ctx: Context, _param: Any, value: bool) -> None:
    if not value or ctx.resilient_parsing:
        return
    click.echo(get_version(short=True))
    ctx.exit()


OPTIONS = [
    option(
        "--version",
        is_flag=True,
        callback=handle_version_option,
        expose_value=False,
        is_eager=True,
        allow_from_autoenv=False,
    ),
    option(
        "--datadir",
        help="Directory for storing Raiden data.",
        default="~/.raiden",
        type=ExpandablePath(
            exists=False,
            dir_okay=True,
            file_okay=False,
            writable=True,
            resolve_path=True,
            allow_dash=False,
        ),
        show_default=True,
        is_eager=True,
    ),
    option(
        "--config-file",
        help="Configuration file (TOML)",
        default=os.path.join("${datadir}", "config.toml"),
        type=PathRelativePath(
            file_okay=True, dir_okay=False, exists=False, readable=True, resolve_path=True
        ),
        is_eager=True,
        show_default=True,
        option_parser_cls=ConfigParser,
        option_parser_priority=1,
    ),
    option(
        "--keystore-path",
        help=(
            "If you have a non-standard path for the Ethereum keystore directory"
            " provide it using this argument."
        ),
        default=None,
        type=ExpandablePath(exists=True),
        show_default=True,
    ),
    option(
        "--address",
        help=(
            "The Ethereum address you would like Raiden to use and for which "
            "a keystore file exists in your local system."
        ),
        default=None,
        type=ADDRESS_TYPE,
        show_default=True,
    ),
    option(
        "--password-file",
        help="Text file containing the password for the provided account",
        default=None,
        type=ExpandableFile(lazy=True),
        show_default=True,
    ),
    option(
        "--user-deposit-contract-address",
        help="hex encoded address of the User Deposit contract.",
        type=ADDRESS_TYPE,
    ),
    option(
        ETH_CHAINID_OPTION,
        "chain_id",
        help=(
            "Specify the chain name/id of the Ethereum network to run Raiden on.\n"
            "Available networks:\n"
            '"mainnet" - chain id: 1\n'
            '"ropsten" - chain id: 3\n'
            '"rinkeby" - chain id: 4\n'
            '"goerli" - chain id: 5\n'
            '"kovan" - chain id: 42\n'
            '"<CHAIN_ID>": use the given chain id directly\n'
        ),
        type=ChainChoiceType(["mainnet", "ropsten", "rinkeby", "goerli", "kovan", "<CHAIN_ID>"]),
        default="mainnet",
        show_default=True,
    ),
    option(
        "--environment-type",
        help=(
            "Specify the environment (production or development).\n"
            'The "production" setting adds some safety measures and is mainly intended '
            "for running Raiden on the mainnet.\n"
        ),
        type=EnumChoiceType(Environment),
        default=Environment.PRODUCTION.value,
        show_default=True,
    ),
    option(
        "--development-environment",
        help=(
            "Choose which set of services and transport servers should be used. "
            "Change this only when you are developing Raiden itself."
        ),
        type=EnumChoiceType(ContractDevEnvironment),
        default=ContractDevEnvironment.DEMO.value,
    ),
    option(
        "--accept-disclaimer",
        help="Bypass the experimental software disclaimer prompt",
        is_flag=True,
    ),
    option(
        "--blockchain-query-interval",
        help="Time interval after which to check for new blocks (in seconds)",
        default=DEFAULT_BLOCKCHAIN_QUERY_INTERVAL,
        show_default=True,
        type=click.FloatRange(min=0.1),
    ),
    option_group(
        "Channel-specific Options",
        option(
            "--default-reveal-timeout",
            help="Sets the default reveal timeout to be used to newly created channels",
            default=DEFAULT_REVEAL_TIMEOUT,
            show_default=True,
            type=click.IntRange(min=1),
        ),
        option(
            "--default-settle-timeout",
            help="Sets the default settle timeout to be used to newly created channels",
            default=DEFAULT_SETTLE_TIMEOUT,
            show_default=True,
            type=click.IntRange(min=20),
        ),
    ),
    option_group(
        "Ethereum Node Options",
        option(
            "--sync-check/--no-sync-check",
            help="Checks if the Ethereum node is synchronized against etherscan.",
            default=True,
            show_default=True,
        ),
        option(
            "--gas-price",
            help=(
                "Set the gas price for Ethereum transactions.\n"
                "Available options:\n"
                '"fast" - transactions are usually mined within 60 seconds\n'
                '"normal" - transactions are usually mined within 5 minutes\n'
            ),
            type=GasPriceChoiceType(["normal", "fast"]),
            default="fast",
            show_default="fast",
        ),
        option(
            ETH_RPC_CONFIG_OPTION,
            help=(
                '"host:port" address of Ethereum JSON-RPC server.\n'
                "Also accepts a protocol prefix (http:// or https://) with optional port"
            ),
            default="http://127.0.0.1:8545",  # geth default jsonrpc port
            type=str,
            show_default=True,
        ),
    ),
    option_group(
        "Raiden Services Options",
        option(
            "--routing-mode",
            help=(
                "Specify the routing mode to be used.\n"
                '"pfs": use the path finding service\n'
                '"private": only use direct channels and don\'t send updates to the PFS\n'
            ),
            type=EnumChoiceType(RoutingMode),
            default=RoutingMode.PFS.value,
            show_default=True,
        ),
        option(
            "--pathfinding-service-address",
            help=(
                f"URL to the Raiden path finding service to request paths from.\n "
                f"Example: https://pfs-ropsten.services-dev.raiden.network\n "
                f"Can also be given the '{MATRIX_AUTO_SELECT_SERVER}' value "
                f"so that Raiden chooses a PFS randomly from the service "
                f"registry contract."
            ),
            default=MATRIX_AUTO_SELECT_SERVER,
            type=str,
            show_default=True,
        ),
        option(
            "--pathfinding-max-paths",
            help="Set maximum number of paths to be requested from the path finding service.",
            default=DEFAULT_PATHFINDING_MAX_PATHS,
            type=int,
            show_default=True,
        ),
        option(
            "--pathfinding-max-fee",
            help="Set max fee per request paid to the path finding service.",
            default=DEFAULT_PATHFINDING_MAX_FEE,
            type=int,
            show_default=True,
        ),
        option(
            "--pathfinding-iou-timeout",
            help="Number of blocks before a new IOU to the path finding service expires.",
            default=DEFAULT_PATHFINDING_IOU_TIMEOUT,
            type=int,
            show_default=True,
        ),
        option(
            "--enable-monitoring/--no-enable-monitoring",
            help="Enable broadcasting of balance proofs to the monitoring services.",
            default=False,
        ),
    ),
    option_group(
        "Matrix Transport Options",
        option(
            "--matrix-server",
            help=(
                f"Matrix homeserver to use for communication.\n"
                f"Valid values:\n"
                f"'{MATRIX_AUTO_SELECT_SERVER}' - automatically select a suitable homeserver\n"
                f"A URL pointing to a Raiden matrix homeserver"
            ),
            default=MATRIX_AUTO_SELECT_SERVER,
            type=MatrixServerType([MATRIX_AUTO_SELECT_SERVER, "<url>"]),
            show_default=True,
        ),
    ),
    option_group(
        "Logging Options",
        option(
            "--log-config",
            help="Log level configuration.\n"
            "Format: [<logger-name-1>]:<level>[,<logger-name-2>:level][,...]",
            type=LOG_LEVEL_CONFIG_TYPE,
            default=":info",
            show_default=True,
        ),
        option(
            "--log-file",
            help="file path for logging to file",
            default=None,
            type=ExpandablePath(dir_okay=False, writable=True, resolve_path=True),
            show_default=True,
        ),
        option("--log-json/--no-log-json", help="Output log lines in JSON format"),
        option(
            "--debug-logfile-path",
            help=(
                "The absolute path to the debug logfile. If not given defaults to:\n"
                " - OSX: ~/Library/Logs/Raiden/raiden_debug_XXX.log\n"
                " - Windows: ~/Appdata/Roaming/Raiden/raiden_debug_XXX.log\n"
                " - Linux: ~/.raiden/raiden_debug_XXX.log\n"
                "\nIf there is a problem with expanding home it is placed under /tmp"
            ),
            type=ExpandablePath(dir_okay=False, writable=True, resolve_path=True),
        ),
        option(
            "--debug-logfile/--no-debug-logfile",
            " /--disable-debug-logfile",
            default=True,
            help=(
                "Enable the debug logfile feature. This is independent of "
                "the normal logging setup. [default: enabled]"
            ),
        ),
    ),
    option_group(
        "RPC Options",
        option(
            "--rpc/--no-rpc",
            help="Start with or without the RPC server.",
            default=True,
            show_default=True,
            is_eager=True,
        ),
        option(
            "--rpccorsdomain",
            help="Comma separated list of domains to accept cross origin requests.",
            default="http://localhost:*/*",
            type=str,
            show_default=True,
        ),
        option(
            "--api-address",
            help='"host:port" for the RPC server to listen on.',
            default=f"127.0.0.1:{DEFAULT_HTTP_SERVER_PORT}",
            type=str,
            show_default=True,
        ),
        option(
            "--web-ui/--no-web-ui",
            help=(
                "Start with or without the web interface. Requires --rpc. "
                "It will be accessible at http://<api-address>. "
            ),
            default=True,
            show_default=True,
        ),
        option(
            "--enable-tracing",
            help=("Enable Jaeger tracing logs."),
            is_flag=True,
            show_default=True,
        ),
    ),
    option_group(
        "Debugging options",
        option(
            "--flamegraph",
            help=("Directory to save stack data used to produce flame graphs."),
            type=ExpandablePath(
                exists=False,
                dir_okay=True,
                file_okay=False,
                writable=True,
                resolve_path=True,
                allow_dash=False,
            ),
            default=None,
        ),
        option(
            "--switch-tracing/--no-switch-tracing", help="Enable switch tracing", default=False
        ),
        option(
            "--unrecoverable-error-should-crash",
            help=(
                "DO NOT use, unless you know what you are doing. If provided "
                "along with a production environment setting then all "
                "unrecoverable errors will lead to a crash and not simply get logged."
            ),
            is_flag=True,
            default=False,
        ),
        option(
            "--log-memory-usage-interval",
            help="Log memory usage every X sec (fractions accepted). [default: disabled]",
            type=float,
            default=0,
        ),
    ),
    option_group(
        "Hash Resolver Options",
        option(
            "--resolver-endpoint",
            help=(
                "URL of the resolver server that is used to resolve "
                "a payment hash to a secret. "
                "Accepts a protocol prefix (http:// or https://) with optional port"
            ),
            default=None,
            type=str,
            show_default=True,
        ),
    ),
    option_group(
        "Mediation Fee Options",
        option(
            "--flat-fee",
            help=(
                "Sets the flat fee required for every mediation in wei of the "
                "mediated token for a certain token address. Must be bigger "
                f"or equal to {FLAT_MED_FEE_MIN}."
            ),
            type=(ADDRESS_TYPE, click.IntRange(min=FLAT_MED_FEE_MIN)),
            multiple=True,
        ),
        option(
            "--proportional-fee",
            help=(
                "Mediation fee as ratio of mediated amount in parts-per-million "
                "(10^-6) for a certain token address. "
                f"Must be in [{PROPORTIONAL_MED_FEE_MIN}, {PROPORTIONAL_MED_FEE_MAX}]."
            ),
            type=(
                ADDRESS_TYPE,
                click.IntRange(min=PROPORTIONAL_MED_FEE_MIN, max=PROPORTIONAL_MED_FEE_MAX),
            ),
            multiple=True,
        ),
        option(
            "--proportional-imbalance-fee",
            help=(
                "Set the worst-case imbalance fee relative to the channels capacity "
                "in parts-per-million (10^-6) for a certain token address. "
                f"Must be in [{IMBALANCE_MED_FEE_MIN}, {IMBALANCE_MED_FEE_MAX}]."
            ),
            type=(
                ADDRESS_TYPE,
                click.IntRange(min=IMBALANCE_MED_FEE_MIN, max=IMBALANCE_MED_FEE_MAX),
            ),
            multiple=True,
        ),
        option(
            "--cap-mediation-fees/--no-cap-mediation-fees",
            help="Cap the mediation fees to never get negative.",
            default=True,
            show_default=True,
        ),
    ),
]

if find_spec("IPython"):
    OPTIONS.append(
        option(
            "--console/--no-console", help="Start the interactive Raiden console", default=False
        )
    )
else:

    def unsupported(_ctx: Any, _param: Any, value: bool) -> None:
        if value:
            raise click.BadParameter("Console support is only available in development installs.")

    OPTIONS.append(
        option("--console/--no-console", hidden=True, callback=unsupported, default=False)
    )


def options(func: Callable) -> Callable:
    """Having the common app options as a decorator facilitates reuse."""
    for option_ in reversed(OPTIONS):
        func = option_(func)
    return func


@group(
    invoke_without_command=True,
    context_settings={"max_content_width": 120},
)
@options
@click.pass_context
def run(ctx: Context, **kwargs: Any) -> None:
    return _run(ctx=ctx, **kwargs)


def _run(ctx: Context, **kwargs: Any) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    switch_monitor = None
    profiler = None
    memory_logger = None
    try:

        configure_logging(
            kwargs["log_config"],
            log_json=kwargs["log_json"],
            log_file=kwargs["log_file"],
            disable_debug_logfile=not kwargs["debug_logfile"],
            debug_log_file_path=kwargs["debug_logfile_path"],
        )

        if kwargs["config_file"] is not None:
            source = ctx.get_parameter_source("config_file")  # type: ignore
            set_by = source.name.title() if source else None
            log.debug("Using config file", config_file=kwargs["config_file"], set_by=set_by)

        enable_monitoring_signal()

        if ctx.invoked_subcommand is not None:
            return

        flamegraph = kwargs.pop("flamegraph", None)
        switch_tracing = kwargs.pop("switch_tracing", None)

        if flamegraph:  # pragma: no cover
            windows_not_supported("flame graph")
            from raiden.utils.profiling.sampler import FlameGraphCollector, TraceSampler

            os.makedirs(flamegraph, exist_ok=True)

            now = datetime.datetime.now().isoformat()
            address = to_checksum_address(kwargs["address"])
            stack_path = os.path.join(flamegraph, f"{address}_{now}_stack.data")
            stack_stream = open(stack_path, "w")
            flame = FlameGraphCollector(stack_stream)
            profiler = TraceSampler(flame)

        if switch_tracing is True:  # pragma: no cover
            windows_not_supported("switch tracing")
            from raiden.utils.profiling.greenlets import SwitchMonitoring

            switch_monitor = SwitchMonitoring()

        if kwargs["environment_type"] == Environment.DEVELOPMENT:
            IDLE.enable()

        log_memory_usage_interval = kwargs.pop("log_memory_usage_interval", 0)
        if log_memory_usage_interval > 0:  # pragma: no cover
            windows_not_supported("memory usage logging")
            from raiden.utils.profiling.memory import MemoryLogger

            memory_logger = MemoryLogger(log_memory_usage_interval)
            memory_logger.start()

        # Name used in the exception handlers, make sure the kwargs contains the
        # key with the correct name by always running it.
        name_or_id = ID_TO_CHAINNAME.get(kwargs["chain_id"], kwargs["chain_id"])

        raiden_version = get_version(short=True)
        click.secho(f"Welcome to Raiden, version {raiden_version}!", fg="green")

        # construct the config here, so that eventual misconfigurations can raise
        # before the disclaimer and before starting any services

        web_ui, rpc = kwargs.get("web_ui"), kwargs.get("rpc")

        if rpc is not True and web_ui is True:

            rpc_param = ctx.command.opt_name_to_param["rpc"]  # type: ignore
            web_ui_param = ctx.command.opt_name_to_param["web_ui"]  # type: ignore
            msg = (
                f"RPC has to be enabled (`{' / '.join(rpc_param.opts)}` option) for option "
                f"`{' / '.join(web_ui_param.opts)}`!"
                f" Disabling Web-UI option automatically."
            )
            click.secho(msg, fg="yellow")
            kwargs["web_ui"] = False

        raiden_config = setup_raiden_config(**kwargs)
        kwargs["config"] = raiden_config
        enable_monitoring = kwargs["enable_monitoring"]
        if enable_monitoring is False:
            is_mainnet = kwargs["chain_id"] == ChainID(1)

            if is_mainnet:
                msg = (
                    "WARNING: You did not enable monitoring (`--enable-monitoring`) while "
                    "connecting to the Ethereum mainnet.\n"
                    "Be aware that you could lose funds when "
                    "disconnecting unintentionally!"
                )
                click.secho(msg, bold=True, fg="red")

        click.secho(
            textwrap.dedent(
                """\
                +------------------------------------------------------------------------+
                | This is a Beta version of experimental open source software released   |
                | as a test version under an MIT license and may contain errors and/or   |
                | bugs. No guarantee or representation whatsoever is made regarding its  |
                | suitability (or its use) for any purpose or regarding its compliance   |
                | with any applicable laws and regulations. Use of the software is at    |
                | your own risk and discretion and by using the software you warrant and |
                | represent that you have read this disclaimer, understand its contents, |
                | assume all risk related thereto and hereby release, waive, discharge   |
                | and covenant not to hold liable Brainbot Labs Establishment or any of  |
                | its officers, employees or affiliates from and for any direct or       |
                | indirect damage resulting from the software or the use thereof.        |
                | Such to the extent as permissible by applicable laws and regulations.  |
                |                                                                        |
                | Privacy warning: Please be aware, that by using the Raiden Client,     |
                | among others your Ethereum address, channels, channel deposits,        |
                | settlements and the Ethereum address of your channel counterparty will |
                | be stored on the Ethereum chain, i.e. on servers of Ethereum node      |
                | operators and ergo are to a certain extent publicly available. The     |
                | same might also be stored on systems of parties running Raiden nodes   |
                | connected to the same token network. Data present in the Ethereum      |
                | chain is very unlikely to be able to be changed, removed or deleted    |
                | from the public arena.                                                 |
                |                                                                        |
                | Also be aware, that data on individual Raiden token transfers will be  |
                | made available via the Matrix protocol to the recipient,               |
                | intermediating nodes of a specific transfer as well as to the Matrix   |
                | server operators, see Raiden Transport Specification.                  |
                +------------------------------------------------------------------------+"""
            ),
            fg="yellow",
        )
        if not kwargs["accept_disclaimer"]:
            click.confirm(
                "\nHave you read, understood and hereby accept the above "
                "disclaimer and privacy warning?",
                abort=True,
            )

        enable_tracing = kwargs["enable_tracing"]
        if enable_tracing:
            tracing_config = Config(
                config={
                    "sampler": {"type": "const", "param": "1"},
                    "logging": True,
                    "tags": {
                        "raiden.client.version": get_version(short=True),
                        "raiden.client.type": "Python",
                    },
                },
                service_name="raiden_client",
                scope_manager=GeventScopeManager(),
                validate=True,
            )
            # Tracer is stored in `opentracing.tracer`
            tracing_config.initialize_tracer(io_loop=IOLoop.current())

            enable_pfs_request_tracing()

        # TODO:
        # - Ask for confirmation to quit if there are any locked transfers that did
        # not timeout.
        run_services(kwargs)
    except KeyboardInterrupt:
        # The user requested a shutdown. Assume that if the exception
        # propagated all the way to the top-level everything was shutdown
        # properly.
        #
        # Notes about edge cases:
        # - It could happen the exception was handled somewhere else in the
        # code, and did not reach the top-level, ideally that should result in
        # an exit with a non-zero code, but currently there is not way to
        # detect that.
        # - Just because the exception reached main, it doesn't mean that all
        # services were properly cleaned up. Ideally at this stage we should
        # run extra code to verify the state of the main services, and if any
        # of the is not properly shutdown exit with a non-zero code.
        pass
    except (ReplacementTransactionUnderpriced, EthereumNonceTooLow) as ex:
        click.secho(
            f"{ex}. Please make sure that this Raiden node is the "
            f"only user of the selected account",
            fg="red",
        )
        sys.exit(ReturnCode.ETH_ACCOUNT_ERROR)
    except (ConnectionError, ConnectTimeout, RequestsConnectionError, ReadTimeoutError):
        print(COMMUNICATION_ERROR.format(kwargs["eth_rpc_endpoint"]))
        sys.exit(ReturnCode.GENERIC_COMMUNICATION_ERROR)
    except EthNodeInterfaceError as e:
        click.secho(str(e), fg="red")
        sys.exit(ReturnCode.ETH_INTERFACE_ERROR)
    except RaidenUnrecoverableError as ex:
        write_stack_trace(ex)
        sys.exit(ReturnCode.FATAL)
    except APIServerPortInUseError as ex:
        click.secho(
            f"ERROR: API Address {ex} is in use. Use --api-address <host:port> "
            f"to specify a different port.",
            fg="red",
        )
        sys.exit(ReturnCode.PORT_ALREADY_IN_USE)
    except (KeystoreAuthenticationError, KeystoreFileNotFound) as e:
        click.secho(str(e), fg="red")
        sys.exit(ReturnCode.ETH_ACCOUNT_ERROR)
    except ConfigurationError as e:
        click.secho(str(e), fg="red")
        sys.exit(ReturnCode.RAIDEN_CONFIGURATION_ERROR)
    except AddressWithoutCode as e:
        click.secho(
            f"{e}. This may happen if an external ERC20 smart contract "
            f"selfdestructed, or if the configured address is misconfigured, make "
            f"sure the used address is not a normal account but a smart contract, "
            f"and that it is deployed to {name_or_id}.",
            fg="red",
        )
        sys.exit(ReturnCode.SMART_CONTRACTS_CONFIGURATION_ERROR)
    except filelock.Timeout:
        click.secho(
            f"FATAL: Another Raiden instance already running for account "
            f"{to_checksum_address(kwargs['address'])} on network id {name_or_id}",
            fg="red",
        )
        sys.exit(ReturnCode.RAIDEN_CONFIGURATION_ERROR)
    except Exception as ex:
        write_stack_trace(ex)
        sys.exit(ReturnCode.FATAL)
    finally:  # pragma: no cover
        # teardown order is important because of side-effects, both the
        # switch_monitor and profiler could use the tracing api, for the
        # teardown code to work correctly the teardown has to be done in the
        # reverse order of the initialization.
        if switch_monitor is not None:
            switch_monitor.stop()
        if memory_logger is not None:
            memory_logger.stop()
        if profiler is not None:
            profiler.stop()


# List of available options, used by the scenario player
FLAG_OPTIONS = {param.name.replace("_", "-") for param in run.params if param.is_flag}
FLAG_OPTIONS = FLAG_OPTIONS.union({"no-" + opt for opt in FLAG_OPTIONS})
KNOWN_OPTIONS = {param.name.replace("_", "-") for param in run.params}.union(FLAG_OPTIONS)


@run.command()
@option("--short", is_flag=True, help="Only display Raiden version")
@click.pass_context
def version(ctx: Context, short: bool) -> None:
    """Print version information and exit."""
    click.echo(get_version(short=short))
    ctx.exit(0)


@run.command()
@option(
    "--report-path",
    help="Store report at this location instead of a temp file.",
    type=ExpandablePath(dir_okay=False, writable=True, resolve_path=True),
)
@option("--debug", is_flag=True, help="Drop into pdb on errors.")
@option(
    "--eth-client",
    type=EnumChoiceType(EthClient),
    default=EthClient.GETH.value,
    show_default=True,
    help="Which Ethereum client to run for the smoketests",
)
@click.pass_context
def smoketest(
    ctx: Context, debug: bool, eth_client: EthClient, report_path: Optional[str]
) -> None:  # pragma: no cover
    return _smoketest(ctx=ctx, debug=debug, eth_client=eth_client, report_path=report_path)


def _smoketest(
    ctx: Context, debug: bool, eth_client: EthClient, report_path: Optional[str]
) -> None:  # pragma: no cover
    """Test, that the Raiden installation is sane."""
    from raiden.tests.utils.smoketest import run_smoketest, setup_smoketest, step_printer

    raiden_stdout = StringIO()

    assert ctx.parent, MYPY_ANNOTATION
    environment_type = ctx.parent.params["environment_type"]
    debug_logfile = ctx.parent.params["debug_logfile"]

    if report_path is None:
        report_file = mktemp(suffix=".log")
    else:
        report_file = report_path

    click.secho(f"Report file: {report_file}", fg="yellow")

    configure_logging(
        logger_level_config={"": "DEBUG"},
        log_file=report_file,
        disable_debug_logfile=not debug_logfile,
    )

    def append_report(subject: str, data: Optional[AnyStr] = None) -> None:
        with open(report_file, "a", encoding="UTF-8") as handler:
            handler.write(f'{f" {subject.upper()} ":=^80}{os.linesep}')
            if data is not None:
                write_data: str
                if isinstance(data, bytes):
                    write_data = data.decode()
                else:
                    write_data = data
                handler.writelines([write_data + os.linesep])

    append_report("Raiden version", json.dumps(get_system_spec()))
    append_report("Raiden log")

    free_port_generator = get_free_port()
    try:
        with step_printer(step_count=8, stdout=sys.stdout) as print_step:
            with setup_smoketest(
                eth_client=eth_client,
                print_step=print_step,
                free_port_generator=free_port_generator,
                debug=debug,
                stdout=raiden_stdout,
                append_report=append_report,
            ) as setup:

                args = setup.args
                port = next(free_port_generator)

                args["api_address"] = f"localhost:{port}"
                args["environment_type"] = environment_type

                # Matrix server
                args["one_to_n_contract_address"] = "0x" + "1" * 40
                args["routing_mode"] = RoutingMode.PFS
                args["flat_fee"] = ()
                args["proportional_fee"] = ()
                args["proportional_imbalance_fee"] = ()

                @group(invoke_without_command=True, use_option_parsers=False)
                @options
                def _setup_raiden_config(**kwargs: Any) -> None:
                    raiden_config = setup_raiden_config(**kwargs)
                    args["config"] = raiden_config
                    args.update(kwargs)
                    return

                # This will run all the generated `args` through the parsing,
                # and fill in missing values by their CLI defaults

                # If no empty `args` is provided, it would use sys.argv[1:] and thus the
                # call args for the outer smoketest() method
                call_args: List[str] = []
                _setup_raiden_config(
                    args=call_args, default_map=args.copy(), standalone_mode=False
                )
                run_smoketest(print_step=print_step, setup=setup)

            append_report("Raiden Node stdout", raiden_stdout.getvalue())

    except:  # noqa pylint: disable=bare-except
        if debug:
            import pdb

            pdb.post_mortem()  # pylint: disable=no-member

        error = traceback.format_exc()
        append_report("Smoketest execution error", error)
        print_step("Smoketest execution error", error=True)
        success = False
    else:
        print_step("Smoketest successful")
        success = True

    if not success:
        sys.exit(1)
