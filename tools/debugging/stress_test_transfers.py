#!/usr/bin/env python
from gevent import monkey  # isort:skip

monkey.patch_all()  # isort:skip

import logging.config
import os
import os.path
import signal
import sys
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from itertools import chain, count, product, repeat
from time import time
from typing import Any, Callable, Dict, Iterable, Iterator, List, NewType, Optional

import gevent
import gevent.os
import requests
import structlog
from eth_utils import is_checksum_address, to_canonical_address, to_checksum_address
from gevent.greenlet import Greenlet
from gevent.pool import Pool
from gevent.subprocess import DEVNULL, STDOUT, Popen
from greenlet import greenlet

from raiden.network.transport.matrix.rtc.utils import setup_asyncio_event_loop
from raiden.network.utils import get_free_port
from raiden.transfer.state import NetworkState
from raiden.utils.formatting import pex
from raiden.utils.nursery import Janitor, Nursery
from raiden.utils.typing import Address, Host, Port, TokenAmount

setup_asyncio_event_loop()

BaseURL = NewType("BaseURL", str)
Amount = NewType("Amount", int)
URL = NewType("URL", str)
TransferPath = List["RunningNode"]
INITIATOR = 0
TARGET = -1

processors: List[Callable] = [
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
Scheduler = Callable[[List[TransferPath], TransferPlan], Iterator["Transfer"]]


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
    starting_balances: Dict[Address, TokenAmount]


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

    # List of transfers, these must satisfy the following requirements:
    #
    # - Every channel in the path must have at LEAST `capacity_lower_bound`.
    transfers: List[TransferPath]

    # Different concurrency levels used to stress the system.
    concurrency: List[int]

    # List of planners (functions that return a list of transfers) that satisfy
    # the following requirements:
    #
    # - The plan MAY use UP TO the `capacity_lower_bound`, but no more.
    planners: List[TransferPlanGenerator]

    # List of schedulers (functions that receive a `TransferPath` and a
    # `TransferPlan`), and decide the order in which these should be executed.
    schedulers: List[Scheduler]


@dataclass
class Transfer:
    path: TransferPath
    amount: Amount


def is_ready(base_url: str) -> bool:
    try:
        result = requests.get(f"{base_url}/api/v1/status").json()
    except KeyError:
        log.info(f"Server {base_url} returned invalid json data.")
    except requests.ConnectionError:
        log.info(f"Waiting for the server {base_url} to start.")
    except requests.RequestException:
        log.exception(f"Request to server {base_url} failed.")
    else:
        if result["status"] == "ready":
            log.info(f"Server {base_url} ready.")
            return True

        log.info(f"Waiting for server {base_url} to become ready, status={result['status']}.")

    return False


def wait_for_status_ready(base_url: str, retry_timeout: int) -> None:
    """Keeps polling for the `/status` endpoint until the status is `ready`."""
    while not is_ready(base_url):
        gevent.sleep(retry_timeout)


def wait_for_reachable(
    transfers: List[TransferPath], token_address: str, retry_timeout: int
) -> None:
    """Wait until the nodes used for the transfers can see each other."""

    # Deduplicate the URLs for the channels which need reachability testing
    channels_not_reachable = set()
    for transfer in transfers:
        for payer, payee in zip(transfer, transfer[1:]):
            channel_url = f"{payer.url}/api/v1/channels/{token_address}/{payee.config.address}"
            channels_not_reachable.add(channel_url)

    # Now wait until every reachability constraint is satisfied
    while channels_not_reachable:
        log.info(f"Waiting for reachability of partner nodes: {channels_not_reachable}")

        for url in channels_not_reachable.copy():
            response = requests.get(url, headers={"Content-Type": "application/json"})
            data = response.json()

            # The return data **may** be `None`, this looks like a race
            # condition in the Raiden client REST API.
            if data and data.get("network_state") == NetworkState.REACHABLE.value:
                channels_not_reachable.remove(url)

        if channels_not_reachable:
            gevent.sleep(retry_timeout)


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
        return RunningNode(process, node, running_url, get_balance_for_node(running_url))

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
    assert is_json, (response.headers["Content-Type"], response.text)
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

    # This can not use `throw`, `propagate_error` is linked with a
    # `FailureSpawnedLink`, which means the code is not executed inside the
    # Hub.
    def propagate_error(result: Greenlet) -> None:
        current.kill(result.exception)

    # TODO: This should return a dictionary, were the key is `(from, to)`  and
    # the amount is the sum of all transfer values, this can then be used to
    # assert on the change of capacity from each running node.
    for transfer in transfers:
        task: Greenlet = pool.spawn(
            transfer_and_assert_successful,
            base_url=transfer.path[INITIATOR].url,
            token_address=token_address,
            target_address=transfer.path[TARGET].config.address,
            payment_identifier=next(identifier_generator),
            amount=transfer.amount,
        )

        # Failure detection. Without linking the exception this loop would have
        # to complete before `pool.join` can be called, since the loop can be
        # considerably large (in the tens of thousands) the delay is
        # perceptible, linking the exception will break the loop as soon as
        # possible, this means the only use of the `join` bellow is to wait for
        # all the greenlets to finish before returning.
        #
        # TODO: Consider abstracting by adding to the nursery a Pool
        # implementation. The pool would spawn new greenlets as slots became
        # available (just like the gevent's implementation), but it would stop
        # if any of the spawned grenlets fails with an exception.
        task.link_exception(propagate_error)

    pool.join(raise_error=True)


# TODO: Expand `paths_direct_transfers` to work with graphs. Any sequence of
# paths from a graph that preserve the `capacity_lower_bound` will work.
def paths_direct_transfers(running_nodes: List[RunningNode]) -> List[TransferPath]:
    """Given the list of `running_nodes`, where each adjacent pair has a channel open,
    return a list of `(from, to)` which will do a direct transfer using each
    channel.
    """
    forward = [[from_, to_] for from_, to_ in zip(running_nodes[:-1], running_nodes[1:])]
    backward = [[to_, from_] for from_, to_ in zip(running_nodes[:-1], running_nodes[1:])]
    return forward + backward


# TODO: Expand `paths_for_mediated_transfers` to work with graphs. Any sequence
# of paths from a graph that *do not* overlap will work with the current
# assumptions. Overlapping paths are acceptable, iff the channels that overlap
# have twice the `capacity_lower_bound`
def paths_for_mediated_transfers(running_nodes: List[RunningNode]) -> List[TransferPath]:
    """Given the list of `running_nodes`, where each adjacent pair has a channel open,
    return the a list with the pair `(from, to)` which are the furthest apart.
    """
    msg = (
        "This function needs to be improved to generate all mediator paths for "
        "a chain with more than 3 running_nodes"
    )
    assert len(running_nodes) == 3, msg
    return [list(running_nodes)] + [list(reversed(running_nodes))]


def scheduler_preserve_order(paths: List[TransferPath], plan: TransferPlan) -> Iterator[Transfer]:
    """Execute the same plan for each path, in order.

    E.g.:

    >>> paths = [[a, b], [b, c]]
    >>> transfer_plan = [1,1]
    >>> scheduler_preserve_order(paths, transfer_plan)
    ... [Transfer([a, b], amount=1),
    ...  Transfer([a, b], amount=1),
    ...  Transfer([b, c], amount=1),
    ...  Transfer([b, c], amount=1)]
    """
    # product works fine with generators
    for path, transfer in product(paths, plan):
        yield Transfer(path, Amount(transfer))


def run_profiler(
    nursery: Nursery, running_nodes: List[RunningNode], profiler_data_directory: str
) -> List[Popen]:
    os.makedirs(os.path.expanduser(profiler_data_directory), exist_ok=True)

    profiler_processes: List[Popen] = []
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


def get_balance_for_node(url: URL) -> Dict[Address, TokenAmount]:
    response = requests.get(f"{url}/api/v1/channels")
    assert response.headers["Content-Type"] == "application/json", response.headers["Content-Type"]
    assert response.status_code == HTTPStatus.OK, response.json()

    response_data = response.json()
    return {channel["partner_address"]: channel["balance"] for channel in response_data}


def wait_for_balance(running_nodes: List[RunningNode]) -> None:
    """Wait until the nodes have `starting_balance`, again

    This makes sure that we can run another iteration of the stress test
    """
    for node in running_nodes:
        balances = get_balance_for_node(node.url)

        while any(bal < start_bal for bal, start_bal in zip(balances, node.starting_balances)):
            gevent.sleep(0.1)
            balances = get_balance_for_node(node.url)


def wait_for_user_input() -> None:
    print("All nodes are ready! Press Enter to continue and perform the stress tests.")

    gevent.os.tp_read(sys.stdin.fileno(), n=1)


def run_stress_test(
    nursery: Nursery, running_nodes: List[RunningNode], config: StressTestConfiguration
) -> None:
    identifier_generator = count(start=FIRST_VALID_PAYMENT_ID)
    profiler_processes: List[Popen] = []

    # TODO: Add tests with fees. This may require changes to the transfer plan,
    # since ATM it depends only in the `capacity_lower_bound` settings.
    for iteration in config.iteration_counter:
        log.info(f"Starting iteration {iteration}")

        # The configuration has to be re-created on every iteration because the
        # port numbers change
        plan = StressTestPlan(
            transfers=paths_for_mediated_transfers(running_nodes),
            concurrency=[50],
            planners=[do_fifty_transfer_up_to],
            schedulers=[scheduler_preserve_order],
        )

        # TODO: Before running the first plan each node should be queried for
        # their channel status. The script should assert the open channels have
        # at least `capacity_lower_bound` together.
        for concurent_paths, concurrency, transfer_planner, scheduler in zip(
            repeat(plan.transfers), plan.concurrency, plan.planners, plan.schedulers
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

            wait_for_reachable(plan.transfers, config.token_address, config.retry_timeout)

            # TODO: `do_transfers` should return the amount of tokens
            # transferred with each `(from, to)` pair, and the total amount
            # must be lower than the `capacity_lower_bound`.
            do_transfers(
                transfers=transfers,
                token_address=config.token_address,
                identifier_generator=identifier_generator,
                pool_size=concurrency,
            )

            wait_for_balance(running_nodes)

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

    nodes_config: List[NodeConfig] = []

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
        iteration_counter: Any = count()
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
