#!/usr/bin/env python
from gevent import monkey  # isort:skip
import logging.config
import os
import os.path
import signal
import sys
from dataclasses import dataclass, field
from datetime import datetime
from http import HTTPStatus
from itertools import chain, count, product
from time import time
from typing import Callable, Dict, Iterable, Iterator, List, NewType, NoReturn, Optional

import gevent
import gevent.os
import requests
import structlog
from eth_utils import is_checksum_address, to_canonical_address, to_checksum_address
from gevent.greenlet import Greenlet
from gevent.pool import Pool
from gevent.subprocess import DEVNULL, STDOUT, Popen
from greenlet import greenlet

from raiden.network.utils import get_free_port
from raiden.utils.formatting import pex
from raiden.utils.nursery import Janitor, Nursery
from raiden.utils.typing import Address, Host, Port, TokenAmount

monkey.patch_all()  # isort:skip

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa
gevent.spawn(asyncio.get_event_loop().run_forever)  # isort:skip # noqa


BaseURL = NewType("BaseURL", str)
Amount = NewType("Amount", int)
URL = NewType("URL", str)

processors = [
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]
structlog.reset_defaults()
logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "colorized-formatter": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.dev.ConsoleRenderer(colors=True),
                "foreign_pre_chain": processors,
            }
        },
        "handlers": {
            "colorized-handler": {
                "class": "logging.StreamHandler",
                "level": "DEBUG",
                "formatter": "colorized-formatter",
            }
        },
        "loggers": {"": {"handlers": ["colorized-handler"], "propagate": True}},
    }
)
structlog.configure(
    processors=processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
    wrapper_class=structlog.stdlib.BoundLogger,
    logger_factory=structlog.stdlib.LoggerFactory(),
)

log = structlog.get_logger(__name__)
log.setLevel("DEBUG")

NO_ROUTE_ERROR = 409
UNBUFERRED = 0
FIRST_VALID_PAYMENT_ID = 1
WAIT_FOR_SOCKET_TO_BE_AVAILABLE = 60

# A partial transfer plan is a list of transfers which is guaranteed to succeed
# (regardless of the order), however the channels won't be restored to their
# initial state after the plan execution, plans of this type MUST be processed
# with `complete_planner_from_partial_planner` to revert the transfers and
# restore the channel state.
PartialTransferPlan = Iterator[Amount]

# A transfer plan is a list of transfer amounts where every transfer WILL be
# **successfully** executed and the channels restored to their initial state.
TransferPlan = Iterator[Amount]

PartialTransferPlanGenerator = Callable[[Amount], Iterator[PartialTransferPlan]]
TransferPlanGenerator = Callable[[Amount], TransferPlan]
Scheduler = Callable[[List["InitiatorAndTarget"], TransferPlan], Iterator["Transfer"]]


@dataclass
class InitialNodeConfig:
    """The configuration of a node provided by the user, this node is not yet
    running.
    """

    args: List[str]
    base_url: BaseURL


@dataclass
class NodeConfig:
    """Configuration of a node after the address has been recovered, this
    contains the expected address of the node.
    """

    args: List[str]
    interface: Host
    address: str
    data_dir: str


@dataclass
class RunningNode:
    """A running node, this has a Raiden instance running in the background
    in a separate process.
    """

    process: Popen
    config: NodeConfig
    url: URL
    starting_balances: Dict[Address, TokenAmount] = field(default_factory=dict)


@dataclass
class InitiatorAndTarget:
    """Description of the origin and target of a transfers."""

    initiator: RunningNode
    target: RunningNode


@dataclass
class StressTestConfiguration:
    port_generator: Iterator[Port]
    retry_timeout: int
    capacity_lower_bound: Amount
    token_address: str
    iteration_counter: Iterable[int]
    profiler_data_directory: Optional[str]


@dataclass
class StressTestPlan:
    # These values can NOT be iterables because they will be consumed multiple
    # times.

    # List of `InitiatorAndTarget` that satisfy the following requirements:
    #
    # - Every `InitiatorAndTarget` must have at LEAST
    # `capacity_lower_bound` in every route.
    initiator_target_pairs: List[List[InitiatorAndTarget]]

    # Different concurrency levels used to stress the system.
    concurrency: List[int]

    # List of planners (functions that return a list of transfers) that satisfy
    # the following requirements:
    #
    # - The plan MAY use UP TO the `capacity_lower_bound`, but no more.
    planners: List[TransferPlanGenerator]

    # List of schedulers (functions that receive a `InitiatorAndTarget` and a
    # `TransferPlan`), and decide the order in which these should be executed.
    schedulers: List[Scheduler]


@dataclass
class Transfer:
    from_to: InitiatorAndTarget
    amount: Amount


def is_ready(base_url: str) -> bool:
    try:
        result = requests.get(f"{base_url}/api/v1/status").json()
        return result["status"] == "ready"
    except KeyError:
        log.info(f"Server {base_url} returned invalid json data.")
    except requests.ConnectionError:
        log.info(f"Waiting for the server {base_url} to start.")
    except requests.RequestException:
        log.exception(f"Request to server {base_url} failed.")

    return False


def wait_for_status_ready(base_url: str, retry_timeout: int) -> None:
    """Keeps polling for the `/status` endpoint until the status is `ready`."""
    while not is_ready(base_url):
        gevent.sleep(retry_timeout)

    raise RuntimeError("Stopping")


def start_and_wait_for_server(
    nursery: Nursery, port_generator: Iterator[Port], node: NodeConfig, retry_timeout: int
) -> Optional[RunningNode]:
    """Start the Raiden node and waits for the REST API to be available,
    returns None if the script is being shutdown.
    """
    # redirect the process output for debugging
    os.makedirs(os.path.expanduser(node.data_dir), exist_ok=True)
    stdout = open(os.path.join(node.data_dir, "stress_test.out"), "a")

    port = next(port_generator)
    api_url = f"{node.interface}:{port}"
    running_url = URL(f"http://{api_url}")

    process_args = node.args + ["--api-address", api_url]
    process = nursery.exec_under_watch(
        process_args, bufsize=UNBUFERRED, stdout=stdout, stderr=STDOUT
    )

    if process is not None:
        wait_for_status_ready(running_url, retry_timeout)
        return RunningNode(process, node, running_url)

    return None


def start_and_wait_for_all_servers(
    nursery: Nursery,
    port_generator: Iterator[Port],
    nodes_config: List[NodeConfig],
    retry_timeout: int,
) -> Optional[List[RunningNode]]:
    """Starts all nodes under the nursery, returns a list of `RunningNode`s or
    None if the script is shuting down.

    Important Note:

    `None` is not always returned if the script is shutting down! Due to race
    conditions it is possible for all processes to be spawned, and only
    afterwards the nursery is closed. IOW: At this stage `None` will only be
    returned if spawning the process fails (e.g. the binary name is wrong),
    however, if the subprocess is spawned and runs for some time, and *then*
    crashes, `None` will **not** be returned here (e.g. if the ethereum node is
    not available). For the second case, the `stop_event` will be set.

    Because of the above, for proper error handling, checking only the return
    value is **not** sufficient. The most reliable approach is to execute new
    logic in greenlets spawned with `spawn_under_watch` and let errors fall
    through.
    """
    greenlets = set(
        nursery.spawn_under_watch(
            start_and_wait_for_server, nursery, port_generator, node, retry_timeout
        )
        for node in nodes_config
    )

    all_running_nodes = []
    for g in gevent.joinall(greenlets, raise_error=True):
        running_node = g.get()

        if running_node is None:
            return None

        all_running_nodes.append(running_node)

    return all_running_nodes


def restart_and_wait_for_server(
    nursery: Nursery, port_generator: Iterator[Port], node: RunningNode, retry_timeout: int
) -> Optional[RunningNode]:
    """Stop `RunningNode` and start it again under the nursery, returns None if
    the script is shuting down.
    """
    node.process.send_signal(signal.SIGINT)

    # Wait for the process to completely shutdown, this is necessary because
    # concurrent usage of the database is not allowed.
    exit_code = node.process.result.get()
    if exit_code != 0:
        raise Exception(f"Node did not shut down cleanly {node!r}")

    return start_and_wait_for_server(nursery, port_generator, node.config, retry_timeout)


def restart_network(
    nursery: Nursery,
    port_generator: Iterator[Port],
    running_nodes: List[RunningNode],
    retry_timeout: int,
) -> Optional[List[RunningNode]]:
    """Stop all `RunningNode`s and start them again under the nursery, returns
    None if the script is shuting down.
    """
    greenlets = set(
        nursery.spawn_under_watch(
            restart_and_wait_for_server, nursery, port_generator, node, retry_timeout
        )
        for node in running_nodes
    )

    all_running_nodes = []
    for g in gevent.joinall(greenlets, raise_error=True):
        running_node = g.get()

        if running_node is None:
            return None

        all_running_nodes.append(running_node)

    return all_running_nodes


def transfer_and_assert_successful(
    base_url: str, token_address: str, target_address: str, payment_identifier: int, amount: int
) -> None:
    # TODO: Add an UUID to the transfer, change Raiden to log the UUID and for
    # it to forward the data to the PFS, which also should log the UUID. This
    # should make debugging easier.

    post_url = f"{base_url}/api/v1/payments/{token_address}/{target_address}"
    json = {"amount": amount, "identifier": payment_identifier}

    log.debug("Payment request", url=post_url, json=json)

    start = time()
    response = requests.post(post_url, json=json)
    elapsed = time() - start

    assert response is not None, "request.post returned None"
    is_json = response.headers["Content-Type"] == "application/json"
    assert is_json, response.headers["Content-Type"]
    assert response.status_code == HTTPStatus.OK, response.json()

    log.debug("Payment done", url=post_url, json=json, time=elapsed)


def do_fifty_transfer_up_to(capacity_lower_bound: Amount) -> TransferPlan:
    """Generates a plan with 50 transfers of the same value.

    >>> len(do_fifty_transfer_up_to(500))
    ... 50
    >>> do_fifty_transfer_up_to(500)
    ... [10, 10, 10 ..., 10]
    """
    qty_of_transfers = 50
    amount = Amount(capacity_lower_bound // qty_of_transfers)

    for _ in range(qty_of_transfers):
        yield amount


def do_transfers(
    transfers: List[Transfer],
    token_address: str,
    identifier_generator: Iterator[int],
    pool_size: int = None,
) -> None:
    """Concurrently execute `transfers`.

    Note:
        To force serial transfers just provide `pool_size=1`.
    """
    pool = Pool(size=pool_size)

    # The usage of `greenlet` and `Greenlet` is not a mistake. `getcurrent` is
    # a `greenlet` interface, whereas `Greenlet` is a `gevent` interface.
    #
    # Note: Capture the parent thread to propagate the exception, this must not
    # be called inside of `propagate_error`.
    current: greenlet = gevent.getcurrent()

    def propagate_error(result: Greenlet) -> NoReturn:
        current.throw(result.exception)
        raise RuntimeError("Must not switch back, this greenlet is dead.")

    # TODO: This should return a dictionary, were the key is `(from, to)`  and
    # the amount is the sum of all transfer values, this can then be used to
    # assert on the change of capacity from each running node.
    for transfer in transfers:
        task: Greenlet = pool.spawn(
            transfer_and_assert_successful,
            base_url=transfer.from_to.initiator.url,
            token_address=token_address,
            target_address=transfer.from_to.target.config.address,
            payment_identifier=next(identifier_generator),
            amount=transfer.amount,
        )

        # Failure detection. Without linking to the exception, the loop would
        # have to complete before the exception is re-raised, because this loop
        # can be considerably large (in the tens of thousands), the delay is
        # perceptible.
        task.link_exception(propagate_error)

    pool.join(raise_error=True)


# TODO: Expand `paths_direct_transfers` to work with graphs. Any sequence of
# paths from a graph that preserve the `capacity_lower_bound` will work.
def paths_direct_transfers(running_nodes: List[RunningNode]) -> List[InitiatorAndTarget]:
    """Given the list of `running_nodes`, where each adjacent pair has a channel open,
    return a list of `(from, to)` which will do a direct transfer using each
    channel.
    """
    forward = [
        InitiatorAndTarget(from_, to_) for from_, to_ in zip(running_nodes[:-1], running_nodes[1:])
    ]
    backward = [
        InitiatorAndTarget(to_, from_) for from_, to_ in zip(running_nodes[:-1], running_nodes[1:])
    ]
    return forward + backward


# TODO: Expand `paths_for_mediated_transfers` to work with graphs. Any sequence
# of paths from a graph that *do not* overlap will work with the current
# assumptions. Overlapping paths are acceptable, iff the channels that overlap
# have twice the `capacity_lower_bound`
def paths_for_mediated_transfers(running_nodes: List[RunningNode]) -> List[InitiatorAndTarget]:
    """Given the list of `running_nodes`, where each adjacent pair has a channel open,
    return the a list with the pair `(from, to)` which are the furthest apart.
    """
    msg = (
        "This function needs to be improved to generate all mediator paths for "
        "a chain with more than 3 running_nodes"
    )
    assert len(running_nodes) == 3, msg
    return [InitiatorAndTarget(running_nodes[0], running_nodes[-1])] + [
        InitiatorAndTarget(running_nodes[-1], running_nodes[0])
    ]


def scheduler_preserve_order(
    paths: List[InitiatorAndTarget], plan: TransferPlan
) -> Iterator[Transfer]:
    """Execute the same plan for each path, in order.

    E.g.:

    >>> paths = [(a, b), (b, c)]
    >>> transfer_plan = [1,1]
    >>> scheduler_preserve_order(paths, transfer_plan)
    ... [Transfer(InitiatorAndTarget(a, b), amount=1),
    ...  Transfer(InitiatorAndTarget(a, b), amount=1),
    ...  Transfer(InitiatorAndTarget(b, c), amount=1),
    ...  Transfer(InitiatorAndTarget(b, c), amount=1)]
    """
    # product works fine with generators
    for from_to, transfer in product(paths, plan):
        yield Transfer(from_to, Amount(transfer))


def run_profiler(
    nursery: Nursery, running_nodes: List[RunningNode], profiler_data_directory: str
) -> List[Popen]:
    os.makedirs(os.path.expanduser(profiler_data_directory), exist_ok=True)

    profiler_processes: List[Popen] = list()
    for node in running_nodes:
        args = [
            "py-spy",
            "record",
            "--pid",
            str(node.process.pid),
            "--output",
            os.path.join(
                profiler_data_directory,
                f"{node.config.address}-{datetime.utcnow().isoformat()}.data",
            ),
        ]
        profiler = Popen(args, stdout=DEVNULL, stderr=DEVNULL)

        nursery.exec_under_watch(profiler)

    return profiler_processes


def get_balance_for_node(node: RunningNode) -> Dict[Address, TokenAmount]:
    response = requests.get(f"{node.url}/api/v1/channels")
    assert response.headers["Content-Type"] == "application/json", response.headers["Content-Type"]
    assert response.status_code == HTTPStatus.OK, response.json()

    response_data = response.json()
    return {channel["partner_address"]: channel["balance"] for channel in response_data}


def get_starting_balances(running_nodes: List[RunningNode]) -> None:
    for node in running_nodes:
        node.starting_balances = get_balance_for_node(node)


def wait_for_balance(running_nodes: List[RunningNode]) -> None:
    """ Wait until the nodes have `starting_balance`, again

    This makes sure that we can run another iteration of the stress test
    """
    for node in running_nodes:
        # TODO: Instead of an `assert` this code should rely use a different
        # type which is guaranteed to always have the `starting_balances`
        # attribute populated.
        assert node.starting_balances, "The node must have the starting_balances prepoluated"

        balances = get_balance_for_node(node)
        while any(bal < start_bal for bal, start_bal in zip(balances, node.starting_balances)):
            gevent.sleep(0.1)
            balances = get_balance_for_node(node)


def wait_for_user_input() -> None:
    print("All nodes are ready! Press Enter to continue and perform the stress tests.")

    gevent.os.tp_read(sys.stdin.fileno(), n=1)


def run_stress_test(
    nursery: Nursery, running_nodes: List[RunningNode], config: StressTestConfiguration
) -> None:
    identifier_generator = count(start=FIRST_VALID_PAYMENT_ID)
    profiler_processes: List[Popen] = list()

    # TODO: Add tests with fees. This may require changes to the transfer plan,
    # since ATM it depends only in the `capacity_lower_bound` settings.
    for iteration in config.iteration_counter:
        log.info(f"Starting iteration {iteration}")

        # The configuration has to be re-created on every iteration because the
        # port numbers change
        plan = StressTestPlan(
            initiator_target_pairs=[paths_for_mediated_transfers(running_nodes)],
            concurrency=[50],
            planners=[do_fifty_transfer_up_to],
            schedulers=[scheduler_preserve_order],
        )

        get_starting_balances([pair.initiator for pair in plan.initiator_target_pairs[0]])

        # TODO: Before running the first plan each node should be queried for
        # their channel status. The script should assert the open channels have
        # at least `capacity_lower_bound` together.
        for concurent_paths, concurrency, transfer_planner, scheduler in zip(
            plan.initiator_target_pairs, plan.concurrency, plan.planners, plan.schedulers
        ):
            log.info(
                f"Starting run {concurent_paths}, {concurrency}, {transfer_planner}, {scheduler}"
            )

            # The plan MUST be executed successfully until exhaustion,
            # otherwise the next plan may try to use an amount that is not
            # available.
            transfer_plan = transfer_planner(config.capacity_lower_bound)
            transfers = list(scheduler(concurent_paths, transfer_plan))

            if config.profiler_data_directory:
                profiler_processes = run_profiler(
                    nursery, running_nodes, config.profiler_data_directory
                )

            # TODO: `do_transfers` should return the amount of tokens
            # transferred with each `(from, to)` pair, and the total amount
            # must be lower than the `capacity_lower_bound`.
            do_transfers(
                transfers=transfers,
                token_address=config.token_address,
                identifier_generator=identifier_generator,
                pool_size=concurrency,
            )

            wait_for_balance([pair.initiator for pair in plan.initiator_target_pairs[0]])

            # After each `do_transfers` the state of the system must be
            # reset, otherwise there is a bug in the planner or Raiden.
            restarted_nodes = restart_network(
                nursery, config.port_generator, running_nodes, config.retry_timeout
            )

            if restarted_nodes is None:
                return
            else:
                running_nodes = restarted_nodes

            for profiler in profiler_processes:
                profiler.send_signal(signal.SIGINT)


def main() -> None:
    import argparse
    import configparser
    import re

    NODE_SECTION_RE = re.compile("^node[0-9]+")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes-data-dir", default=os.getcwd())
    parser.add_argument("--wait-after-first-sync", default=False, action="store_true")
    parser.add_argument("--profiler-data-directory", default=None)
    parser.add_argument("--interface", default="127.0.0.1")
    parser.add_argument("--iterations", default=5, type=int)
    parser.add_argument("config")
    args = parser.parse_args()

    if args.profiler_data_directory is not None and os.geteuid() != 0:
        raise RuntimeError("To enable profiling the script has to be executed with root.")

    config = configparser.ConfigParser()
    config.read(args.config)

    datadir = args.nodes_data_dir

    interface = Host(args.interface)
    port_generator = get_free_port(5000)
    retry_timeout = 1

    nodes_config: List[NodeConfig] = list()

    token_address = config.defaults()["token-address"]
    if not is_checksum_address(token_address):
        raise ValueError(f"Invalid token address {token_address}, check it is checksummed.")

    defaults = {
        "--log-config": "raiden:DEBUG",
        "--environment-type": "development",
        "--datadir": datadir,
    }

    for section in config:
        if NODE_SECTION_RE.match(section):
            node_config = config[section]
            address = node_config["address"]

            node = defaults.copy()
            node.update(
                {
                    "--keystore-path": node_config["keystore-path"],
                    "--password-file": node_config["password-file"],
                    "--eth-rpc-endpoint": node_config["eth-rpc-endpoint"],
                    "--network-id": node_config["network-id"],
                    "--address": address,
                }
            )

            pathfinding_url = node_config.get("pathfinding-service-address")
            if pathfinding_url is not None:
                node["--pathfinding-service-address"] = pathfinding_url

            raiden_args = [
                "raiden",
                "--accept-disclaimer",
                "--log-json",
                "--disable-debug-logfile",
                "--flat-fee",
                token_address,
                "0",
                "--proportional-fee",
                token_address,
                "0",
                "--proportional-imbalance-fee",
                token_address,
                "0",
            ]
            raiden_args.extend(chain.from_iterable(node.items()))

            # The REST interface uses checksummed address. Normalize it here.
            address = to_checksum_address(address)

            nodedir = os.path.join(datadir, f"node_{pex(to_canonical_address(address))}")
            nodes_config.append(NodeConfig(raiden_args, interface, address, nodedir))

    # TODO: Determine the `capacity_lower_bound` by querying the nodes.
    capacity_lower_bound = 1130220

    profiler_data_directory = args.profiler_data_directory

    iterations = args.iterations
    if iterations is None:
        iteration_counter = count()
    else:
        iteration_counter = iter(range(iterations))

    # def stop_on_signal(sig=None, _frame=None):
    #     stop.set()
    # gevent.signal(signal.SIGQUIT, stop_on_signal)
    # gevent.signal(signal.SIGTERM, stop_on_signal)
    # gevent.signal(signal.SIGINT, stop_on_signal)

    # TODO: If any of the processes crashes the script should collect and
    # bundle the logs.
    #
    # Cleanup with the Janitor is not strictily necessary for the stress test,
    # since once can assume a bug happened and the state of the node is
    # inconsistent, however it is nice to have.
    with Janitor() as nursery:
        nodes_running = start_and_wait_for_all_servers(
            nursery, port_generator, nodes_config, retry_timeout
        )

        if nodes_running is None:
            return

        if args.wait_after_first_sync:
            nursery.spawn_under_watch(wait_for_user_input).get()

        test_config = StressTestConfiguration(
            port_generator,
            retry_timeout,
            Amount(capacity_lower_bound),
            token_address,
            iteration_counter,
            profiler_data_directory,
        )

        nursery.spawn_under_watch(run_stress_test, nursery, nodes_running, test_config)
        nursery.wait(timeout=None)


if __name__ == "__main__":
    # TODO:
    # - The script should quit if the vpn is closed (and therefore the raiden
    # process is killed)
    # - With the janitor the database is properly closed (sqlite's lock
    # goes away), however the filelock's file is not cleared.
    main()
