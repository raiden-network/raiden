#!/usr/bin/python
from gevent import monkey  # isort:skip # noqa

monkey.patch_all()  # isort:skip # noqa

import atexit
import os
import os.path
import signal
from abc import ABC, abstractmethod
from dataclasses import dataclass
from functools import lru_cache
from http import HTTPStatus
from itertools import chain, count, product
from math import ceil, sqrt
from random import randint, shuffle
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
from raiden.utils import pex

log = structlog.get_logger(__name__)
BaseURL = NewType("BaseURL", str)
NO_ROUTE_ERROR = 409
UNBUFERRED = 0
STATUS_CODE_FOR_SUCCESS = 0
FIRST_VALID_PAYMENT_ID = 1

# A transfer plan is a list of transfer amounts were every transfer WILL be
# **successfully** executed for a predetermined path, where **every direction of
# every channel** has at least a capacity larger than the amount of the plan.
# IOW:
#
#   lower_bound = min(min(c.forward_capacity, c.backwards_capacity) for c in channels_in_path)
#   assert lower_bound >= sum(plan)
#
# This allows the script to do the transfers in the given path and assert that
# every transfer is successful.
#
# A partial transfer plan is one that does not guarantee the channels are
# retored to their initial state after execution, plans of this type MUST be
# prossed with `complete_planner_from_partial_planner`.
PartialTransferPlan = Iterator[int]
TransferPlan = Iterator[int]

# A function that generates partial transfer plans.
PartialTransferPlanGenerator = Callable[[int], Iterator[PartialTransferPlan]]

# A function that generates complete transfer plans.
TransferPlanGenerator = Callable[[int], Iterator[TransferPlan]]

# An amount to be used in a transfer
Amount = NewType("Amount", int)


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
    with a separted process.
    """

    process: Popen
    config: NodeConfig


@dataclass
class InitiatorAndTarget:
    """Description of the origin and target of a transfers."""

    initiator: RunningNode
    target: RunningNode


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
    """Tries to properly stop all subprocesses before quiting the script.

    - This watches for the status of the subprocess, if the processes exits
      with a non-zero error code then the failure is propagated.
    - If for any reason this process is dying, then all the spawned processes
      have to be killed in order for a porper clean up to happen.
    """

    def __init__(self, stop: Event) -> None:
        self.stop = stop
        self._processes: Set[Popen] = set()

    def __enter__(self) -> Nursery:
        # Registers an atexit callback in case the __exit__ doesn't get a
        # chance to run. This happens when the Janitor is not used in the main
        # greenlet, and its greenlet is not the one that is dying.
        atexit.register(self._free_resources)

        # Hide the nursery to required the context manager to be used. This
        # leads to better behavior in the happy case since the exit handler is
        # used.
        janitor = self
        stop = self.stop

        class ProcessNursery(Nursery):
            @staticmethod
            def track(process: Popen) -> None:
                janitor._processes.add(process)

                def subprocess_stopped(result: AsyncResult) -> None:
                    # processes are expected to quit while the nursery is
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
                # raise the exceptoin.
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


@lru_cache()
def factorize_number(number: int) -> Iterator[int]:
    """Factorize `number` into its primes.

    Note:
        This function skips the number 1.
        This function yields each prime `n` times, where `n` is how many times
        it can be used to devide `number`.
    """
    if number <= 1:
        raise ValueError("Cannot factorize 1, 0, or negative numbers.")

    # Special case 2 to avoid emitting the same value twice
    if number == 2:
        yield 2
        return

    # Optimization: Do the even numbers on a single step, this reduces the
    # number of candidates in half.
    while number % 2 == 0:
        yield 2
        number //= 2

    # `number` was even
    if number == 1:
        return

    # There cannot be a prime that is larger than `sqrt(number)`, this upper
    # bound drastically reduces the search space.
    upper_bound = sqrt(number)

    # The `+1` covers the corner case were the `sqrt` itself is a factor. E.g.
    # `sqrt(9)` is a factor of `9`, and `range(3,3)` would skip it.
    upper_bound = ceil(upper_bound) + 1

    # skip all even numbers, since they have been processed above
    step = 2
    candidates = range(3, upper_bound, step)

    for candidate in candidates:
        while number % candidate == 0:
            yield candidate
            number //= candidate

    # The last number is also a prime
    if number != 1:
        yield number


def all_proper_divisors(number: int) -> Iterator[int]:
    """Returns all integers that are proper divisors of `number`.

    A proper `divisor` is a number will divides `number` evenly. i.e. `number %
    divisor == 0`.

    Note:
        This does not return the number `1`, otherwise some of the proper
        divisors would be repeated.
    """
    if number <= 1:
        raise ValueError("number must be greater than 0")

    # Create a list from the iterator of `factorize_number` because we have
    # have to iterator over the result multiple times.
    all_factors = list(factorize_number(number))

    for repeat in range(1, len(all_factors) + 1):
        for factors in product(all_factors, repeat=repeat):
            result = 1
            for factor in factors:
                result *= factor

            is_valid_factor = number >= result and number % result == 0
            assert is_valid_factor, f"{result} is not a factor of {number}"

            yield result


def exhaust_number_with(number: int, i: int) -> Iterator[int]:
    """Returns a list of integers that add up to `number`. The list will
    contain the value `i` as many times as possible, the last value will be
    `number % i`.
    """
    iterations, remainder = divmod(number, i)

    for _ in range(iterations):
        yield i

    if remainder:
        yield remainder


def random_numbers_that_add_to(number: int) -> Iterator[int]:
    while number:
        # randint is inclusive on both ends
        current_value = randint(1, number - 1)

        yield current_value
        number -= current_value

        assert number >= 0, f"{number} must not be negative"


def partial_planner_without_remainders_until_exhaustion(
    number: int
) -> Iterator[PartialTransferPlan]:
    """Returns a list of plans where for each plan every transfer has the same
    amount and after the plan is executed the channel is exhausted.
    """
    # Start with the special value `1`, since that is not returned by
    # `all_proper_divisors`
    yield (1 for _ in range(number))

    # Now, for each proper divisor, do the number of transfers necessary so
    # that `number` is exhausted.
    for current_value in all_proper_divisors(number):
        iterations = number / current_value

        msg = "Iterations must be an integer, otherwise there is a bug in `all_proper_divisors`"
        assert isinstance(iterations, int), msg

        yield (current_value for _ in range(iterations))


def partial_planner_with_remainders_until_exhaustion(number: int) -> Iterator[PartialTransferPlan]:
    """Returns a list of plans that exhaust the channel.

    The generated plans will use every amount from 1 up to `amount`, to ensure
    the `number` is exhausted the last value in a plan may be different (i.e.
    the remainder).
    """
    # Increase value until `number` is reached, if the `current_value` value is
    # not a divisor of `number` the remainder is emited as the last amount.
    for current_value in range(1, number + 1):
        yield exhaust_number_with(number, current_value)


def partial_planner_with_random_values_until_exhaustion(
    number: int
) -> Iterator[PartialTransferPlan]:
    """Returns a list of transfer plans with random `amounts` that will exhaust
    the channel.
    """
    iterations = randint(1, 10)

    for _ in range(iterations):
        yield random_numbers_that_add_to(number)


def get_address(base_url: str) -> str:
    return requests.get(f"{base_url}/api/v1/address").text


def wait_for_address_endpoint(base_url: str, retry_timeout: int) -> str:
    """Keeps retrying the `/address` endpoint."""
    while True:
        try:
            address = get_address(base_url)
            log.info(f"{address} finished restarting ready")
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
    node.process.kill(signal.SIGINT)
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

    return requests.post(post_url, json=json)


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


def complete_planner_from_partial_planner(
    partial_plan_generator: PartialTransferPlanGenerator
) -> TransferPlanGenerator:
    """Created a complete plan out of a partial plan.

    The new generated transfer plan will repeat every transfer in the backwards
    direction, this ensures the transfer will restore the channels to their
    original state it is executed.
    """

    def complete_plan_generator(number: int) -> Iterator[TransferPlan]:
        partial_plans = partial_plan_generator(number)

        for partial_plan in partial_plans:
            # save the transfers in the forward direction
            forward_plan = list(partial_plan)

            # add the transfers in the backwards direction to restore to the
            # previous state
            backward_plan = reversed(forward_plan)

            complete_plan = chain(forward_plan, backward_plan)

            yield complete_plan

    return complete_plan_generator


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
    # the amount is the sum of all transfer values, this is can then be used to
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
    return [InitiatorAndTarget(from_, to_) for from_, to_ in zip(running_nodes, running_nodes[1:])]


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
    return [InitiatorAndTarget(running_nodes[0], running_nodes[-1])]


def scheduler_preserve_order(
    paths: List[InitiatorAndTarget], plan: TransferPlan
) -> Iterator[Transfer]:
    for from_to in paths:
        for transfer in plan:
            yield Transfer(from_to, Amount(transfer))


def scheduler_interleave_paths(
    paths: List[InitiatorAndTarget], plan: TransferPlan
) -> Iterator[Transfer]:
    # The difference from the interleaved to the preserve order is just order
    # of the loops bellow.
    for transfer in plan:
        for from_to in paths:
            yield Transfer(from_to, Amount(transfer))


def scheduler_random(paths: List[InitiatorAndTarget], plan: TransferPlan) -> Iterator[Transfer]:
    # TODO: Lazily shuffle
    all_transfers = list(zip(plan, paths))
    shuffle(all_transfers)

    for transfer, from_to in all_transfers:
        yield Transfer(from_to, Amount(transfer))


def run_stress_test(
    nursery: Nursery,
    retry_timeout: int,
    running_nodes: List[RunningNode],
    capacity_lower_bound: int,
    token_address: str,
    iteration_counter: Iterator[int],
) -> None:
    identifier_generator = count(start=FIRST_VALID_PAYMENT_ID)

    for iteration in iteration_counter:
        log.info(f"Starting run {iteration}")

        # Generate all the paths that can be used with the current topology.
        # Note: Every channel direction must have at least
        # `capacity_lower_bound` tokens available.
        all_direct_paths = list(paths_direct_transfers(running_nodes))
        all_mediated_paths = list(paths_for_mediated_transfers(running_nodes))
        all_concurrent_paths = [all_direct_paths, all_mediated_paths]

        # Gradually increase concurrency to stress the system.
        all_concurrency = list(range(1, 5))

        # Different transfer plans to stress the system. Note that for every
        # plan:
        # - The plan MAY use UP TO the available capacity of a channel, but no
        # more, since using more than the available capacity will fail.
        # - The plan MUST return the channel to its initial state, by sending
        # transfers backwards.
        # - The plan MUST be executed successfully until exhaustion,
        # otherwise the next plan may try to use an amount that is not
        # available.
        #
        # TODO: Add plans that work with different fee schedules.
        all_partial_transfers_planners = [
            partial_planner_without_remainders_until_exhaustion,
            partial_planner_with_remainders_until_exhaustion,
            partial_planner_with_random_values_until_exhaustion,
        ]
        all_complete_transfer_planners = [
            complete_planner_from_partial_planner(plan) for plan in all_partial_transfers_planners
        ]

        # Note that:
        # - Every direction of every channel in the topology is expected to
        # have at least `capacity_lower_bound` at the beginning of the plan.
        # - No plan uses more than `capacity_lower_bound` tokens.
        # - Every plan restores the lower bound.
        # Therefore the transfers can be scheduled in any order.
        all_transfers_schedulers = [
            scheduler_preserve_order,
            scheduler_interleave_paths,
            scheduler_random,
        ]

        for concurent_paths, concurrency, transfer_planner, scheduler in zip(
            all_concurrent_paths,
            all_concurrency,
            all_complete_transfer_planners,
            all_transfers_schedulers,
        ):
            # TODO: Before running the first plan each node should be queried
            # for their channel status. The script should assert there are open
            # channels with the partner nodes, and a assert the capacities are
            # lower than `capacity_lower_bound`.
            # TODO: From the above, the `capacity_lower_bound` can be queried
            # from the existing nodes in the test network.

            for transfer_plan in transfer_planner(capacity_lower_bound):
                transfers = list(scheduler(concurent_paths, transfer_plan))

                # TODO: While the transfers are being sent the status of the
                # processes should also be checked (assuming they are local
                # nodes). If any of the processes crashes the script should
                # collect and bundle the logs.
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
            f"'signal.ranliw(greenlet.kill)'."
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

    for section in config:
        if NODE_SECTION_RE.match(section):
            node_config = config[section]
            address = node_config["address"]
            port = next(port_generator)
            api_url = f"{interface}:{port}"

            raiden_args = [
                "raiden",
                "--accept-disclaimer",
                "--environment-type",
                "development",
                "--datadir",
                datadir,
                "--keystore-path",
                node_config["keystore"],
                "--password-file",
                node_config["password-file"],
                "--eth-rpc-endpoint",
                node_config["ethnode"],
                "--network-id",
                node_config["networkid"],
                "--address",
                address,
                "--api-address",
                api_url,
            ]

            if not is_checksum_address(address):
                raise ValueError(f"address {address} is not checksummed.")

            nodedir = os.path.join(datadir, f"node_{pex(to_canonical_address(address))}")
            nodes_config.append(
                NodeConfig(raiden_args, address, BaseURL(f"http://{api_url}"), nodedir)
            )

    iterations = 5
    balance = 1130220
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
            balance,
            token_address,
            iteration_counter,
        )


if __name__ == "__main__":
    # TODO:
    # - The script should quit if the vpn is closed (and therefore the raiden
    # process is killed)
    # - With the janitor the database is properly closed (the sqlite's lock
    # goes away), however the filelock's file is not cleared.
    main()
