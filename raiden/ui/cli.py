import contextlib
import datetime
import json
import os
import signal
import sys
import textwrap
import traceback
from copy import deepcopy
from io import StringIO
from subprocess import TimeoutExpired
from tempfile import mkdtemp, mktemp
from typing import Any, AnyStr, Callable, ContextManager, Dict, List, Optional, Tuple

import click
import structlog
from click import Context
from requests.packages import urllib3
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from raiden.app import App
from raiden.constants import (
    DISCOVERY_DEFAULT_ROOM,
    FLAT_MED_FEE_MIN,
    IMBALANCE_MED_FEE_MAX,
    IMBALANCE_MED_FEE_MIN,
    PROPORTIONAL_MED_FEE_MAX,
    PROPORTIONAL_MED_FEE_MIN,
    Environment,
    EthClient,
    RoutingMode,
)
from raiden.exceptions import EthereumNonceTooLow, ReplacementTransactionUnderpriced
from raiden.log_config import configure_logging
from raiden.network.transport.matrix.utils import make_room_alias
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_BLOCKCHAIN_QUERY_INTERVAL,
    DEFAULT_HTTP_SERVER_PORT,
    DEFAULT_PATHFINDING_IOU_TIMEOUT,
    DEFAULT_PATHFINDING_MAX_FEE,
    DEFAULT_PATHFINDING_MAX_PATHS,
    DEFAULT_REVEAL_TIMEOUT,
    DEFAULT_SETTLE_TIMEOUT,
    RAIDEN_CONTRACT_VERSION,
)
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    EnumChoiceType,
    GasPriceChoiceType,
    MatrixServerType,
    NetworkChoiceType,
    PathRelativePath,
    apply_config_file,
    group,
    option,
    option_group,
    validate_option_dependencies,
)
from raiden.utils.formatting import to_checksum_address
from raiden.utils.http import HTTPExecutor
from raiden.utils.profiling.greenlets import SwitchMonitoring
from raiden.utils.profiling.memory import MemoryLogger
from raiden.utils.profiling.sampler import FlameGraphCollector, TraceSampler
from raiden.utils.system import get_system_spec
from raiden.utils.typing import MYPY_ANNOTATION, TokenAddress
from raiden_contracts.constants import NETWORKNAME_TO_ID

from .runners import EchoNodeRunner, MatrixRunner

log = structlog.get_logger(__name__)
ETH_RPC_CONFIG_OPTION = "--eth-rpc-endpoint"
ETH_NETWORKID_OPTION = "--network-id"


OPTION_DEPENDENCIES: Dict[str, List[Tuple[str, Any]]] = {
    "pathfinding-service-address": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-paths": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-fee": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-iou-timeout": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "enable-monitoring": [("transport", "matrix")],
    "matrix-server": [("transport", "matrix")],
}


def options(func: Callable) -> Callable:
    """Having the common app options as a decorator facilitates reuse."""

    # Until https://github.com/pallets/click/issues/926 is fixed the options need to be re-defined
    # for every use
    options_ = [
        option("--version", hidden=True, is_flag=True, allow_from_autoenv=False),
        option(
            "--datadir",
            help="Directory for storing raiden data.",
            default=lambda: os.path.join(os.path.expanduser("~"), ".raiden"),
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
            "--config-file",
            help="Configuration file (TOML)",
            default=os.path.join("${datadir}", "config.toml"),
            type=PathRelativePath(
                file_okay=True, dir_okay=False, exists=False, readable=True, resolve_path=True
            ),
            show_default=True,
        ),
        option(
            "--keystore-path",
            help=(
                "If you have a non-standard path for the ethereum keystore directory"
                " provide it using this argument."
            ),
            default=None,
            type=click.Path(exists=True),
            show_default=True,
        ),
        option(
            "--address",
            help=(
                "The ethereum address you would like raiden to use and for which "
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
            type=click.File(lazy=True),
            show_default=True,
        ),
        option(
            "--tokennetwork-registry-contract-address",
            help="hex encoded address of the Token Network Registry contract.",
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            "--secret-registry-contract-address",
            help="hex encoded address of the Secret Registry contract.",
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            "--service-registry-contract-address",
            help="hex encoded address of the Service Registry contract.",
            type=ADDRESS_TYPE,
        ),
        option(
            "--one-to-n-contract-address",
            help="hex encoded address of the OneToN contract.",
            type=ADDRESS_TYPE,
        ),
        option(
            "--endpoint-registry-contract-address",
            help="hex encoded address of the Endpoint Registry contract.",
            type=ADDRESS_TYPE,
            show_default=True,
        ),
        option(
            "--user-deposit-contract-address",
            help="hex encoded address of the User Deposit contract.",
            type=ADDRESS_TYPE,
        ),
        option(
            "--monitoring-service-contract-address",
            help="hex encoded address of the Monitorin Service contract.",
            type=ADDRESS_TYPE,
        ),
        option("--console", help="Start the interactive raiden console", is_flag=True),
        option(
            "--transport",
            help="Transport system to use.",
            type=click.Choice(["matrix"]),
            default="matrix",
            show_default=True,
            hidden=True,
        ),
        option(
            ETH_NETWORKID_OPTION,
            help=(
                "Specify the network name/id of the Ethereum network to run Raiden on.\n"
                "Available networks:\n"
                '"mainnet" - network id: 1\n'
                '"ropsten" - network id: 3\n'
                '"rinkeby" - network id: 4\n'
                '"goerli" - network id: 5\n'
                '"kovan" - network id: 42\n'
                '"<NETWORK_ID>": use the given network id directly\n'
            ),
            type=NetworkChoiceType(
                ["mainnet", "ropsten", "rinkeby", "goerli", "kovan", "<NETWORK_ID>"]
            ),
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
            "--accept-disclaimer",
            help="Bypass the experimental software disclaimer prompt",
            is_flag=True,
        ),
        option(
            "--showconfig",
            help="Show all configuration values used to control Raiden's behavior",
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
                type=click.IntRange(min=20),
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
                help="Checks if the ethereum node is synchronized against etherscan.",
                default=True,
                show_default=True,
            ),
            option(
                "--gas-price",
                help=(
                    "Set the gas price for ethereum transactions. If not provided "
                    "the normal gas price startegy is used.\n"
                    "Available options:\n"
                    '"fast" - transactions are usually mined within 60 seconds\n'
                    '"normal" - transactions are usually mined within 5 minutes\n'
                    "<GAS_PRICE> - use given gas price\n"
                ),
                type=GasPriceChoiceType(["normal", "fast"]),
                default="fast",
                show_default=True,
            ),
            option(
                ETH_RPC_CONFIG_OPTION,
                help=(
                    '"host:port" address of ethereum JSON-RPC server.\n'
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
                    '"local": use local routing, but send updates to the PFS\n'
                    '"private": use local routing and don\'t send updates to the PFS\n'
                ),
                type=EnumChoiceType(RoutingMode),
                default=RoutingMode.PFS.value,
                show_default=True,
            ),
            option(
                "--pathfinding-service-address",
                help=(
                    "URL to the Raiden path finding service to request paths from.\n"
                    "Example: https://pfs-ropsten.services-dev.raiden.network\n"
                    'Can also be given the "auto" value so that raiden chooses a '
                    "PFS randomly from the service registry contract"
                ),
                default="auto",
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
                "--enable-monitoring",
                help="Enable broadcasting of balance proofs to the monitoring services.",
                is_flag=True,
            ),
        ),
        option_group(
            "Matrix Transport Options",
            option(
                "--matrix-server",
                help=(
                    "Matrix homeserver to use for communication.\n"
                    "Valid values:\n"
                    '"auto" - automatically select a suitable homeserver\n'
                    "A URL pointing to a Raiden matrix homeserver"
                ),
                default="auto",
                type=MatrixServerType(["auto", "<url>"]),
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
                type=click.Path(dir_okay=False, writable=True, resolve_path=True),
                show_default=True,
            ),
            option("--log-json", help="Output log lines in JSON format", is_flag=True),
            option(
                "--debug-logfile-path",
                help=(
                    "The absolute path to the debug logfile. If not given defaults to:\n"
                    " - OSX: ~/Library/Logs/Raiden/raiden_debug_XXX.log\n"
                    " - Windows: ~/Appdata/Roaming/Raiden/raiden_debug_XXX.log\n"
                    " - Linux: ~/.raiden/raiden_debug_XXX.log\n"
                    "\nIf there is a problem with expanding home it is placed under /tmp"
                ),
                type=click.Path(dir_okay=False, writable=True, resolve_path=True),
            ),
            option(
                "--disable-debug-logfile",
                help=(
                    "Disable the debug logfile feature. This is independent of "
                    "the normal logging setup"
                ),
                is_flag=True,
            ),
        ),
        option_group(
            "RPC Options",
            option(
                "--rpc/--no-rpc",
                help="Start with or without the RPC server.",
                default=True,
                show_default=True,
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
        ),
        option_group(
            "Debugging options",
            option(
                "--flamegraph",
                help=("Directory to save stack data used to produce flame graphs."),
                type=click.Path(
                    exists=False,
                    dir_okay=True,
                    file_okay=False,
                    writable=True,
                    resolve_path=True,
                    allow_dash=False,
                ),
                default=None,
            ),
            option("--switch-tracing", help="Enable switch tracing", is_flag=True, default=False),
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

    for option_ in reversed(options_):
        func = option_(func)
    return func


@group(invoke_without_command=True, context_settings={"max_content_width": 120})
@options
@click.pass_context
def run(ctx: Context, **kwargs: Any) -> None:
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    flamegraph = kwargs.pop("flamegraph", None)
    switch_tracing = kwargs.pop("switch_tracing", None)
    profiler = None
    switch_monitor = None

    if flamegraph:
        os.makedirs(flamegraph, exist_ok=True)

        now = datetime.datetime.now().isoformat()
        address = to_checksum_address(kwargs["address"])
        stack_path = os.path.join(flamegraph, f"{address}_{now}_stack.data")
        stack_stream = open(stack_path, "w")
        flame = FlameGraphCollector(stack_stream)
        profiler = TraceSampler(flame)

    if switch_tracing is True:
        switch_monitor = SwitchMonitoring()

    memory_logger = None
    log_memory_usage_interval = kwargs.pop("log_memory_usage_interval", 0)
    if log_memory_usage_interval > 0:
        memory_logger = MemoryLogger(log_memory_usage_interval)
        memory_logger.start()

    if kwargs.pop("version", False):
        click.echo(
            click.style("Hint: Use ", fg="green")
            + click.style(f"'{os.path.basename(sys.argv[0])} version'", fg="yellow")
            + click.style(" instead", fg="green")
        )
        ctx.invoke(version, short=True)
        return

    if kwargs["config_file"]:
        apply_config_file(run, kwargs, ctx)

    validate_option_dependencies(run, ctx, kwargs, OPTION_DEPENDENCIES)

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    if kwargs["transport"] == "matrix":
        runner = MatrixRunner(kwargs, ctx)
    else:
        # Shouldn't happen
        raise RuntimeError(f"Invalid transport type '{kwargs['transport']}'")

    click.secho(runner.welcome_string, fg="green")
    click.secho(
        textwrap.dedent(
            """\
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
            ----------------------------------------------------------------------"""
        ),
        fg="yellow",
    )
    if not kwargs["accept_disclaimer"]:
        click.confirm(
            "\nHave you read, understood and hereby accept the above "
            "disclaimer and privacy warning?",
            abort=True,
        )

    # TODO:
    # - Ask for confirmation to quit if there are any locked transfers that did
    # not timeout.
    try:
        app = runner.run()
        app.stop()
    except (ReplacementTransactionUnderpriced, EthereumNonceTooLow) as e:
        click.secho(
            "{}. Please make sure that this Raiden node is the "
            "only user of the selected account".format(str(e)),
            fg="red",
        )
        sys.exit(1)
    finally:
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
def version(short: bool) -> None:
    """Print version information and exit. """
    if short:
        print(get_system_spec()["raiden"])
    else:
        print(json.dumps(get_system_spec(), indent=2))


@run.command()
@option(
    "--report-path",
    help="Store report at this location instead of a temp file.",
    type=click.Path(dir_okay=False, writable=True, resolve_path=True),
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
) -> None:
    """ Test, that the raiden installation is sane. """
    from raiden.tests.utils.smoketest import (
        setup_raiden,
        run_smoketest,
        setup_matrix_for_smoketest,
        setup_testchain_for_smoketest,
    )
    from raiden.tests.utils.transport import make_requests_insecure, ParsedURL
    from raiden.utils.debugging import enable_gevent_monitoring_signal

    step_count = 8
    step = 0
    stdout = sys.stdout
    raiden_stdout = StringIO()

    assert ctx.parent, MYPY_ANNOTATION
    environment_type = ctx.parent.params["environment_type"]
    transport = ctx.parent.params["transport"]
    disable_debug_logfile = ctx.parent.params["disable_debug_logfile"]
    matrix_server = ctx.parent.params["matrix_server"]

    if transport != "matrix":
        raise RuntimeError(f"Invalid transport type '{transport}'")

    if report_path is None:
        report_file = mktemp(suffix=".log")
    else:
        report_file = report_path

    enable_gevent_monitoring_signal()
    make_requests_insecure()
    urllib3.disable_warnings(InsecureRequestWarning)

    click.secho(f"Report file: {report_file}", fg="yellow")

    configure_logging(
        logger_level_config={"": "DEBUG"},
        log_file=report_file,
        disable_debug_logfile=disable_debug_logfile,
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

    def print_step(description: str, error: bool = False) -> None:
        nonlocal step
        step += 1
        click.echo(
            "{} {}".format(
                click.style(f"[{step}/{step_count}]", fg="blue"),
                click.style(description, fg="green" if not error else "red"),
            ),
            file=stdout,
        )

    contracts_version = RAIDEN_CONTRACT_VERSION

    try:
        free_port_generator = get_free_port()
        ethereum_nodes = None

        datadir = mkdtemp()
        testchain_manager: ContextManager[Dict[str, Any]] = setup_testchain_for_smoketest(
            eth_client=eth_client,
            print_step=print_step,
            free_port_generator=free_port_generator,
            base_datadir=datadir,
            base_logdir=datadir,
        )
        matrix_manager: ContextManager[
            List[Tuple[ParsedURL, HTTPExecutor]]
        ] = setup_matrix_for_smoketest(
            print_step=print_step,
            free_port_generator=free_port_generator,
            broadcast_rooms_aliases=[
                make_room_alias(NETWORKNAME_TO_ID["smoketest"], DISCOVERY_DEFAULT_ROOM)
            ],
        )

        # Do not redirect the stdout on a debug session, otherwise the REPL
        # will also be redirected
        if debug:
            stdout_manager = contextlib.nullcontext()
        else:
            stdout_manager = contextlib.redirect_stdout(raiden_stdout)

        with stdout_manager, testchain_manager as testchain, matrix_manager as server_urls:
            result = setup_raiden(
                transport=transport,
                matrix_server=matrix_server,
                print_step=print_step,
                contracts_version=contracts_version,
                eth_client=testchain["eth_client"],
                eth_rpc_endpoint=testchain["eth_rpc_endpoint"],
                web3=testchain["web3"],
                base_datadir=testchain["base_datadir"],
                keystore=testchain["keystore"],
            )

            args = result["args"]
            contract_addresses = result["contract_addresses"]
            ethereum_nodes = testchain["node_executors"]
            token = result["token"]

            port = next(free_port_generator)

            args["api_address"] = f"localhost:{port}"
            args["config"] = deepcopy(App.DEFAULT_CONFIG)
            args["environment_type"] = environment_type
            args["extra_config"] = {"transport": {"available_servers": server_urls}}
            args["one_to_n_contract_address"] = "0x" + "1" * 40
            args["routing_mode"] = RoutingMode.PRIVATE
            args["flat_fee"] = ()
            args["proportional_fee"] = ()
            args["proportional_imbalance_fee"] = ()

            for option_ in run.params:
                if option_.name in args.keys():
                    args[option_.name] = option_.process_value(ctx, args[option_.name])
                else:
                    args[option_.name] = option_.default

            try:
                run_smoketest(
                    print_step=print_step,
                    args=args,
                    contract_addresses=contract_addresses,
                    token=token,
                )
            finally:
                if ethereum_nodes:
                    for node_executor in ethereum_nodes:
                        node = node_executor.process
                        node.send_signal(signal.SIGINT)

                        try:
                            node.wait(10)
                        except TimeoutExpired:
                            print_step("Ethereum node shutdown unclean, check log!", error=True)
                            node.kill()

                        if isinstance(node_executor.stdio, tuple):
                            logfile = node_executor.stdio[1]
                            logfile.flush()
                            logfile.seek(0)
                            append_report("Ethereum Node log output", logfile.read())

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
        print_step(f"Smoketest successful")
        success = True

    if not success:
        sys.exit(1)


@run.command(
    help=(
        "Start an echo node.\n"
        "Mainly useful for development.\n"
        "See: https://raiden-network.readthedocs.io/en/stable/api_walkthrough.html"
        "#interacting-with-the-raiden-echo-node"
    )
)
@click.option("--token-address", type=ADDRESS_TYPE, required=True)
@click.pass_context
def echonode(ctx: Context, token_address: TokenAddress) -> None:
    """ Start a raiden Echo Node that will send received transfers back to the initiator. """
    EchoNodeRunner(ctx.obj, ctx, token_address).run()
