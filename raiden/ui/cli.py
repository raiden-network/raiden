import json
import os
import sys
import textwrap
import traceback
from tempfile import mktemp
from typing import Any, AnyStr, Dict, List, Optional, Tuple

import click
import structlog
import urllib3
from mirakuru import ProcessExitedWithError
from urllib3.exceptions import InsecureRequestWarning

from raiden.constants import Environment, EthClient, RoutingMode
from raiden.exceptions import ReplacementTransactionUnderpriced, TransactionAlreadyPending
from raiden.log_config import configure_logging
from raiden.network.sockfactory import SocketFactory
from raiden.network.utils import get_free_port
from raiden.settings import (
    DEFAULT_PATHFINDING_IOU_TIMEOUT,
    DEFAULT_PATHFINDING_MAX_FEE,
    DEFAULT_PATHFINDING_MAX_PATHS,
    INITIAL_PORT,
)
from raiden.ui.startup import environment_type_to_contracts_version
from raiden.utils import get_system_spec
from raiden.utils.cli import (
    ADDRESS_TYPE,
    LOG_LEVEL_CONFIG_TYPE,
    EnumChoiceType,
    GasPriceChoiceType,
    MatrixServerType,
    NATChoiceType,
    NetworkChoiceType,
    PathRelativePath,
    apply_config_file,
    group,
    option,
    option_group,
    validate_option_dependencies,
)

from .runners import EchoNodeRunner, MatrixRunner, UDPRunner

log = structlog.get_logger(__name__)


OPTION_DEPENDENCIES: Dict[str, List[Tuple[str, Any]]] = {
    "pathfinding-service-address": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-paths": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-max-fee": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "pathfinding-iou-timeout": [("transport", "matrix"), ("routing-mode", RoutingMode.PFS)],
    "enable-monitoring": [("transport", "matrix")],
    "matrix-server": [("transport", "matrix")],
    "listen-address": [("transport", "udp")],
    "max-unresponsive-time": [("transport", "udp")],
    "send-ping-time": [("transport", "udp")],
    "nat": [("transport", "udp")],
}


def options(func):
    """Having the common app options as a decorator facilitates reuse."""

    # Until https://github.com/pallets/click/issues/926 is fixed the options need to be re-defined
    # for every use
    options_ = [
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
        option("--console", help="Start the interactive raiden console", is_flag=True),
        option(
            "--transport",
            help="Transport system to use. UDP is not recommended",
            type=click.Choice(["udp", "matrix"]),
            default="matrix",
            show_default=True,
        ),
        option(
            "--network-id",
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
                "--eth-rpc-endpoint",
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
                    '"basic": use local routing\n'
                    '"pfs": use the path finding service\n'
                ),
                type=EnumChoiceType(RoutingMode),
                default=RoutingMode.BASIC.value,
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
            "UDP Transport Options",
            option(
                "--listen-address",
                help='"host:port" for the raiden service to listen on.',
                default="0.0.0.0:{}".format(INITIAL_PORT),
                type=str,
                show_default=True,
            ),
            option(
                "--max-unresponsive-time",
                help=(
                    "Max time in seconds for which an address can send no packets and "
                    "still be considered healthy."
                ),
                default=30,
                type=int,
                show_default=True,
            ),
            option(
                "--send-ping-time",
                help=(
                    "Time in seconds after which if we have received no message from a "
                    "node we have a connection with, we are going to send a PING message"
                ),
                default=60,
                type=int,
                show_default=True,
            ),
            option(
                "--nat",
                help=(
                    "Manually specify method to use for determining public IP / NAT traversal.\n"
                    "Available methods:\n"
                    '"auto" - Try UPnP, then STUN, fallback to none\n'
                    '"upnp" - Try UPnP, fallback to none\n'
                    '"stun" - Try STUN, fallback to none\n'
                    '"none" - Use the local interface address '
                    "(this will likely cause connectivity issues)\n"
                    '"ext:<IP>[:<PORT>]" - manually specify the external IP (and optionally port '
                    "number)"
                ),
                type=NATChoiceType(["auto", "upnp", "stun", "none", "ext:<IP>[:<PORT>]"]),
                default="auto",
                show_default=True,
                option_group="udp_transport",
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
                type=str,
                show_default=True,
            ),
            option("--log-json", help="Output log lines in JSON format", is_flag=True),
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
                default="127.0.0.1:5001",
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
                "--unrecoverable-error-should-crash",
                help=(
                    "DO NOT use, unless you know what you are doing. If provided "
                    "along with a production environment setting then all "
                    "unrecoverable errors will lead to a crash and not simply get logged."
                ),
                is_flag=True,
                default=False,
            ),
        ),
        option_group(
            "Hash Resolver options",
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
    ]

    for option_ in reversed(options_):
        func = option_(func)
    return func


@group(invoke_without_command=True, context_settings={"max_content_width": 120})
@options
@click.pass_context
def run(ctx, **kwargs):
    # pylint: disable=too-many-locals,too-many-branches,too-many-statements

    if kwargs["config_file"]:
        apply_config_file(run, kwargs, ctx)

    validate_option_dependencies(run, ctx, kwargs, OPTION_DEPENDENCIES)

    if ctx.invoked_subcommand is not None:
        # Pass parsed args on to subcommands.
        ctx.obj = kwargs
        return

    if kwargs["transport"] == "udp":
        runner = UDPRunner(kwargs, ctx)
    elif kwargs["transport"] == "matrix":
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
    except (ReplacementTransactionUnderpriced, TransactionAlreadyPending) as e:
        click.secho(
            "{}. Please make sure that this Raiden node is the "
            "only user of the selected account".format(str(e)),
            fg="red",
        )
        sys.exit(1)


@run.command()
@option("--short", is_flag=True, help="Only display Raiden version")
def version(short):
    """Print version information and exit. """
    if short:
        print(get_system_spec()["raiden"])
    else:
        print(json.dumps(get_system_spec(), indent=2))


@run.command()
@option("--debug", is_flag=True, help="Drop into pdb on errors.")
@option(
    "--eth-client",
    type=EnumChoiceType(EthClient),
    default=EthClient.GETH.value,
    show_default=True,
    help="Which Ethereum client to run for the smoketests",
)
@click.pass_context
def smoketest(ctx, debug, eth_client):
    """ Test, that the raiden installation is sane. """
    from raiden.tests.utils.smoketest import setup_testchain_and_raiden, run_smoketest
    from raiden.tests.utils.transport import make_requests_insecure, matrix_server_starter

    report_file = mktemp(suffix=".log")
    configure_logging(
        logger_level_config={"": "DEBUG"},
        log_file=report_file,
        disable_debug_logfile=ctx.parent.params["disable_debug_logfile"],
    )
    free_port_generator = get_free_port()
    click.secho(f"Report file: {report_file}", fg="yellow")

    def append_report(subject: str, data: Optional[AnyStr] = None):
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

    step_count = 7
    if ctx.parent.params["transport"] == "matrix":
        step_count = 8
    step = 0

    stdout = sys.stdout

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

    print_step("Getting smoketest configuration")
    contracts_version = environment_type_to_contracts_version(
        ctx.parent.params["environment_type"]
    )

    with setup_testchain_and_raiden(
        transport=ctx.parent.params["transport"],
        eth_client=eth_client,
        matrix_server=ctx.parent.params["matrix_server"],
        contracts_version=contracts_version,
        print_step=print_step,
        free_port_generator=free_port_generator,
    ) as result:
        args = result["args"]
        contract_addresses = result["contract_addresses"]
        token = result["token"]
        ethereum_nodes = result["ethereum_nodes"]
        # Also respect environment type
        args["environment_type"] = ctx.parent.params["environment_type"]
        for option_ in run.params:
            if option_.name in args.keys():
                args[option_.name] = option_.process_value(ctx, args[option_.name])
            else:
                args[option_.name] = option_.default

        port = next(free_port_generator)

        args["api_address"] = "localhost:" + str(port)

        if args["transport"] == "udp":
            with SocketFactory("127.0.0.1", port, strategy="none") as mapped_socket:
                args["mapped_socket"] = mapped_socket
                success = run_smoketest(
                    print_step=print_step,
                    append_report=append_report,
                    args=args,
                    contract_addresses=contract_addresses,
                    token=token,
                    debug=debug,
                    ethereum_nodes=ethereum_nodes,
                )
        elif args["transport"] == "matrix":
            args["mapped_socket"] = None
            print_step("Starting Matrix transport")
            try:
                with matrix_server_starter(free_port_generator=free_port_generator) as server_urls:
                    # Disable TLS verification so we can connect to the self signed certificate
                    make_requests_insecure()
                    urllib3.disable_warnings(InsecureRequestWarning)
                    args["extra_config"] = {
                        "transport": {"matrix": {"available_servers": server_urls}}
                    }
                    success = run_smoketest(
                        print_step=print_step,
                        append_report=append_report,
                        args=args,
                        contract_addresses=contract_addresses,
                        token=token,
                        debug=debug,
                        ethereum_nodes=ethereum_nodes,
                    )
            except (PermissionError, ProcessExitedWithError, FileNotFoundError):
                append_report("Matrix server start exception", traceback.format_exc())
                print_step(
                    f"Error during smoketest setup, report was written to {report_file}",
                    error=True,
                )
                success = False
        else:
            # Shouldn't happen
            raise RuntimeError(f"Invalid transport type '{args['transport']}'")

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
def echonode(ctx, token_address):
    """ Start a raiden Echo Node that will send received transfers back to the initiator. """
    EchoNodeRunner(ctx.obj, ctx, token_address).run()
