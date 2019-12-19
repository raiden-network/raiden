#!/usr/bin/python
from gevent import monkey  # isort:skip # noqa

monkey.patch_all()  # isort:skip # noqa

import atexit
import os
import os.path
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass
from http import HTTPStatus
from itertools import chain, count, product
from time import time
from types import TracebackType
from typing import Any, Callable, Iterator, List, NewType, NoReturn, Optional, Set, Type

import gevent
import requests
import structlog
from eth_utils import is_checksum_address, to_canonical_address
from gevent.event import AsyncResult, Event
from gevent.greenlet import Greenlet
from gevent.pool import Pool
from gevent.subprocess import STDOUT, Popen
from greenlet import greenlet

from raiden.network.utils import get_free_port
from raiden.utils.formatting import pex

BaseURL = NewType("BaseURL", str)
Amount = NewType("Amount", int)

log = structlog.get_logger(__name__)
NO_ROUTE_ERROR = 409
UNBUFERRED = 0
STATUS_CODE_FOR_SUCCESS = 0
FIRST_VALID_PAYMENT_ID = 1
WAIT_FOR_SOCKET_TO_BE_AVAILABLE = 60

# A partial transfer plan is a list of transfers which is guaranteed to succeed
# (regardless of the order), however the channels won't be restored to their
# initial state after the plan execution, plans of this type MUST be processed
# with `complete_planner_from_partial_planner` to revert the transfers and
# restore the channel state.
PartialTransferPlan = Iterator[Amount]

# A transfer plan is a list of transfer amounts were every transfer WILL be
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
    address: str
    base_url: BaseURL
    data_dir: str


@dataclass
class RunningNode:
    """A running node, this has a Raiden instance running in the background
    in a separate process.
    """

    process: Popen
    config: NodeConfig


@dataclass
class InitiatorAndTarget:
    """Description of the origin and target of a transfers."""

    initiator: RunningNode
    target: RunningNode


@dataclass
class StressTestConfiguration:
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


class Nursery(ABC):
    @abstractmethod
    def track(self, process: Popen) -> None:
        pass

    @abstractmethod
    def spawn_under_watch(self, function: Callable, *args: Any, **kargs: Any) -> Greenlet:
        pass


class Janitor:
    """Tries to properly stop all subprocesses before quitting the script.

    - This watches for the status of the subprocess, if the processes exits
      with a non-zero error code then the failure is propagated.
    - If for any reason this process is dying, then all the spawned processes
      have to be killed in order for a proper clean up to happen.
    """

    def __init__(self, stop: Event) -> None:
        self.stop = stop
        self._processes: Set[Popen] = set()

    def __enter__(self) -> Nursery:
        # Registers an atexit callback in case the __exit__ doesn't get a
        # chance to run. This happens when the Janitor is not used in the main
        # greenlet, and its greenlet is not the one that is dying.
        atexit.register(self._free_resources)

        # Hide the nursery to require the context manager to be used. This
        # leads to better behavior in the happy case since the exit handler is
        # used.
        janitor = self
        stop = self.stop

        class ProcessNursery(Nursery):
            @staticmethod
            def track(process: Popen) -> None:
                janitor._processes.add(process)

                def subprocess_stopped(result: AsyncResult) -> None:
                    # Processes are expected to quit while the nursery is
                    # active, remove them from the track list to clear memory
                    janitor._processes.remove(process)

                    # if the subprocess error'ed propagate the error.
                    if result.get() != STATUS_CODE_FOR_SUCCESS:
                        log.error("Raiden died! Bailing out.")
                        stop.set()

                process.result.rawlink(subprocess_stopped)

            @staticmethod
            def spawn_under_watch(function: Callable, *args: Any, **kwargs: Any) -> Greenlet:
                greenlet = gevent.spawn(function, *args, **kwargs)

                # The Event.rawlink is executed inside the Hub thread, which
                # does validation and *raises on blocking calls*, to go around
                # this a new greenlet has to be spawned, that in turn will
                # raise the exception.
                def spawn_to_kill() -> None:
                    gevent.spawn(greenlet.throw, gevent.GreenletExit())

                stop.rawlink(lambda _stop: spawn_to_kill())
                return greenlet

        return ProcessNursery()

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        traceback: Optional[TracebackType],
    ) -> Optional[bool]:
        # Make sure to signal that we are exiting. This is a noop if the signal
        # is set already (e.g. because a subprocess exited with a non-zero
        # status code)
        self.stop.set()

        # Behave nicely if context manager's __exit__ is executed. This
        # implements the expected behavior of a context manager, which will
        # clear the resources when exiting.
        atexit.unregister(self._free_resources)

        self._free_resources()

        return None

    def _free_resources(self) -> None:
        for p in self._processes:
            p.send_signal(signal.SIGINT)


def get_address(base_url: str) -> str:
    return requests.get(f"{base_url}/api/v1/address").text


def wait_for_address_endpoint(base_url: str, retry_timeout: int) -> str:
    """Keeps retrying the `/address` endpoint."""
    while True:
        try:
            address = get_address(base_url)
            log.info(f"{address} finished (re)starting and is ready")
            return address
        except requests.ConnectionError:
            log.info(f"Waiting for the server {base_url} to start.")
        except requests.RequestException:
            log.exception(f"Request to server {base_url} failed.")

        gevent.sleep(retry_timeout)

    raise RuntimeError("Stopping")


def start_and_wait_for_server(
    nursery: Nursery, node: NodeConfig, retry_timeout: int
) -> RunningNode:
    # redirect the process output for debugging
    os.makedirs(node.data_dir, exist_ok=True)
    stdout = open(os.path.join(node.data_dir, "stress_test.out"), "a")

    process = Popen(node.args, bufsize=UNBUFERRED, stdout=stdout, stderr=STDOUT)

    nursery.track(process)

    wait_for_address_endpoint(node.base_url, retry_timeout)
    return RunningNode(process, node)


def start_and_wait_for_all_servers(
    nursery: Nursery, nodes_config: List[NodeConfig], retry_timeout: int
) -> List[RunningNode]:
    greenlets = set(
        nursery.spawn_under_watch(start_and_wait_for_server, nursery, node, retry_timeout)
        for node in nodes_config
    )
    gevent.joinall(greenlets, raise_error=True)
    running_nodes = [g.get() for g in greenlets]
    return running_nodes


def kill_restart_and_wait_for_server(
    nursery: Nursery, node: RunningNode, retry_timeout: int
) -> RunningNode:
    node.process.send_signal(signal.SIGINT)
    gevent.sleep(WAIT_FOR_SOCKET_TO_BE_AVAILABLE)
    return start_and_wait_for_server(nursery, node.config, retry_timeout)


def restart_network(
    nursery: Nursery, running_nodes: List[RunningNode], retry_timeout: int
) -> List[RunningNode]:
    greenlets = [
        nursery.spawn_under_watch(kill_restart_and_wait_for_server, nursery, node, retry_timeout)
        for node in running_nodes
    ]
    gevent.wait(greenlets)
    return [g.get() for g in greenlets]


def do_transfer(post_url: str, identifier: int, amount: int) -> requests.Response:
    # TODO: Add an UUID to the transfer, change Raiden to log the UUID and for
    # it to forward the data to the PFS, which also should log the UUID. This
    # should make debugging easier.
    json = {"amount": amount, "identifier": identifier}

    log.debug("Payment request", url=post_url, json=json)

    start = time()
    response = requests.post(post_url, json=json)
    elapsed = time() - start

    log.debug("Payment done", url=post_url, json=json, time=elapsed)

    return response


def transfer_and_assert_successful(
    base_url: str, token_address: str, target_address: str, payment_identifier: int, amount: int
) -> None:
    response = do_transfer(
        f"{base_url}/api/v1/payments/{token_address}/{target_address}", payment_identifier, amount
    )

    assert response is not None
    is_json = response.headers["Content-Type"] == "application/json"
    assert is_json, response.headers["Content-Type"]
    assert response.status_code == HTTPStatus.OK, response.json()


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
            base_url=transfer.from_to.initiator.config.base_url,
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


def run_stress_test(
    nursery: Nursery,
    retry_timeout: int,
    running_nodes: List[RunningNode],
    capacity_lower_bound: Amount,
    token_address: str,
    iteration_counter: Iterator[int],
) -> None:
    identifier_generator = count(start=FIRST_VALID_PAYMENT_ID)

    config = StressTestConfiguration(
        initiator_target_pairs=[paths_for_mediated_transfers(running_nodes)],
        concurrency=[10, 20],
        planners=[do_fifty_transfer_up_to],
        schedulers=[scheduler_preserve_order],
    )

    # TODO: Add tests with fees. This may require changes to the transfer plan,
    # since ATM it depends only in the `capacity_lower_bound` settings.
    for iteration in iteration_counter:
        log.info(f"Starting iteration {iteration}")
        # TODO: Before running the first plan each node should be queried for
        # their channel status. The script should assert the open channels have
        # at least `capacity_lower_bound` together.
        for concurent_paths, concurrency, transfer_planner, scheduler in zip(
            config.initiator_target_pairs, config.concurrency, config.planners, config.schedulers
        ):
            log.info(
                f"Starting run {concurent_paths}, {concurrency}, {transfer_planner}, {scheduler}"
            )

            # The plan MUST be executed successfully until exhaustion,
            # otherwise the next plan may try to use an amount that is not
            # available.
            transfer_plan = transfer_planner(capacity_lower_bound)
            transfers = list(scheduler(concurent_paths, transfer_plan))

            # TODO: `do_transfers` should return the amount of tokens
            # transferred with each `(from, to)` pair, and the total amount
            # must be lower than the `capacity_lower_bound`.
            do_transfers(
                transfers=transfers,
                token_address=token_address,
                identifier_generator=identifier_generator,
                pool_size=concurrency,
            )

            # After each `do_transfers` the state of the system must be
            # reset, otherwise there is a bug in the planner or Raiden.
            restart_network(nursery, running_nodes, retry_timeout)


# TODO: cancel the spawn_later if `greenlet` exits normally.
def force_quit(stop: Event, greenlet: greenlet, timeout: int) -> None:
    """If the process does not stop because of the signal, kill it. This will
    execute the `__exit__` handler that will do the cleanup.
    """

    def kill_greenlet(_stop: Event) -> None:
        error = RuntimeError(
            f"Greenlet {greenlet} had to be forcefully killed. This happened "
            f"because there is a piece of code that is doing blocking IO and is "
            f"not monitored by the 'stop' signal. To fix this the code doing the "
            f"IO operations has to be executed inside a greenlet, and then the "
            f"subgreenlet has to be linked to the stop signal with "
            f"'signal.rawlink(greenlet.kill)'."
        )
        gevent.spawn_later(timeout, greenlet.throw, error)

    stop.rawlink(kill_greenlet)


def main() -> None:
    import argparse
    import configparser
    import re

    NODE_SECTION_RE = re.compile("^node[0-9]+")

    parser = argparse.ArgumentParser()
    parser.add_argument("--nodes-data-dir", default=os.getcwd())
    parser.add_argument("interface", default="127.0.0.1")
    parser.add_argument("config")
    args = parser.parse_args()

    config = configparser.ConfigParser()
    config.read(args.config)

    datadir = args.nodes_data_dir

    interface = args.interface
    port_generator = get_free_port(5000)
    retry_timeout = 1

    nodes_config: List[NodeConfig] = list()
    nodes_running: List[RunningNode] = list()

    defaults = {
        "--log-config": "raiden:DEBUG",
        "--environment-type": "development",
        "--datadir": datadir,
    }

    for section in config:
        if NODE_SECTION_RE.match(section):
            node_config = config[section]
            address = node_config["address"]
            port = next(port_generator)
            api_url = f"{interface}:{port}"

            node = defaults.copy()
            node.update(
                {
                    "--keystore-path": node_config["keystore-path"],
                    "--password-file": node_config["password-file"],
                    "--eth-rpc-endpoint": node_config["eth-rpc-endpoint"],
                    "--network-id": node_config["network-id"],
                    "--address": address,
                    "--api-address": api_url,
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
                "0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7",
                "0",
                "--proportional-fee",
                "0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7",
                "0",
                "--proportional-imbalance-fee",
                "0xf9BA8aDF7F7024D7de8eB37b4c981CFFe3C88Ea7",
                "0",
            ]
            raiden_args.extend(chain.from_iterable(node.items()))

            if not is_checksum_address(address):
                raise ValueError(f"address {address} is not checksummed.")

            nodedir = os.path.join(datadir, f"node_{pex(to_canonical_address(address))}")
            nodes_config.append(
                NodeConfig(raiden_args, address, BaseURL(f"http://{api_url}"), nodedir)
            )

    # TODO: Determine the `capacity_lower_bound` by querying the nodes.
    capacity_lower_bound = 1130220

    iterations = 5
    token_address = config.defaults()["token-address"]

    if not is_checksum_address(token_address):
        raise ValueError(f"Invalid token address {token_address}, check it is checksummed.")

    if iterations is None:
        iteration_counter = count()
    else:
        iteration_counter = iter(range(iterations))

    stop = Event()

    force_quit(stop, gevent.getcurrent(), timeout=5)

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
    with Janitor(stop) as nursery:
        nodes_running = start_and_wait_for_all_servers(nursery, nodes_config, retry_timeout)

        # If any of the processes failed to startup
        if stop.is_set():
            return

        nursery.spawn_under_watch(
            run_stress_test,
            nursery,
            retry_timeout,
            nodes_running,
            capacity_lower_bound,
            token_address,
            iteration_counter,
        ).get()


if __name__ == "__main__":
    # TODO:
    # - The script should quit if the vpn is closed (and therefore the raiden
    # process is killed)
    # - With the janitor the database is properly closed (sqlite's lock
    # goes away), however the filelock's file is not cleared.
    main()
