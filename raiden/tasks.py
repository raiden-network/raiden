import re
from json.decoder import JSONDecodeError

import click
import gevent
import requests
import structlog
from eth_utils import to_checksum_address, to_hex
from gevent.event import AsyncResult
from pkg_resources import parse_version
from web3 import Web3

from raiden.constants import (
    CHECK_GAS_RESERVE_INTERVAL,
    CHECK_NETWORK_ID_INTERVAL,
    CHECK_RDN_MIN_DEPOSIT_INTERVAL,
    CHECK_VERSION_INTERVAL,
    LATEST,
    RELEASE_PAGE,
    SECURITY_EXPRESSION,
)
from raiden.exceptions import EthNodeCommunicationError
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import MIN_REI_THRESHOLD
from raiden.utils import gas_reserve, to_rdn
from raiden.utils.runnable import Runnable
from raiden.utils.typing import Callable, List, Tuple

REMOVE_CALLBACK = object()
log = structlog.get_logger(__name__)


def _do_check_version(current_version: Tuple[str, ...]):
    content = requests.get(LATEST).json()
    if "tag_name" not in content:
        # probably API rate limit exceeded
        click.secho(
            "Error while contacting github for latest version. API rate limit exceeded?", fg="red"
        )
        return False
    # getting the latest release version
    latest_release = parse_version(content["tag_name"])
    security_message = re.search(SECURITY_EXPRESSION, content["body"])
    if security_message:
        click.secho(security_message.group(0), fg="red")
        # comparing it to the user's application
    if current_version < latest_release:
        msg = "You're running version {}. The latest version is {}".format(
            current_version, latest_release
        )
        click.secho(msg, fg="red")
        click.secho(f"It's time to update! Releases: {RELEASE_PAGE}", fg="red")
        return False
    return True


def check_version(current_version: str):  # pragma: no unittest
    """ Check periodically for a new release """
    app_version = parse_version(current_version)
    while True:
        try:
            _do_check_version(app_version)
        except requests.exceptions.HTTPError as herr:
            click.secho("Error while checking for version", fg="red")
            print(herr)
        except ValueError as verr:
            click.secho("Error while checking the version", fg="red")
            print(verr)
        finally:
            # repeat the process once every 3h
            gevent.sleep(CHECK_VERSION_INTERVAL)


def check_gas_reserve(raiden):  # pragma: no unittest
    """ Check periodically for gas reserve in the account """
    while True:
        has_enough_balance, estimated_required_balance = gas_reserve.has_enough_gas_reserve(
            raiden, channels_to_open=1
        )
        estimated_required_balance_eth = Web3.fromWei(estimated_required_balance, "ether")

        if not has_enough_balance:
            log.info("Missing gas reserve", required_wei=estimated_required_balance)
            click.secho(
                (
                    "WARNING\n"
                    "Your account's balance is below the estimated gas reserve of "
                    f"{estimated_required_balance_eth} eth. This may lead to a loss of "
                    "of funds because your account will be unable to perform on-chain "
                    "transactions. Please add funds to your account as soon as possible."
                ),
                fg="red",
            )

        gevent.sleep(CHECK_GAS_RESERVE_INTERVAL)


def check_rdn_deposits(raiden, user_deposit_proxy: UserDeposit):  # pragma: no unittest
    """ Check periodically for RDN deposits in the user-deposits contract """
    while True:
        rei_balance = user_deposit_proxy.effective_balance(raiden.address, "latest")
        rdn_balance = to_rdn(rei_balance)
        if rei_balance < MIN_REI_THRESHOLD:
            click.secho(
                (
                    f"WARNING\n"
                    f"Your account's RDN balance of {rdn_balance} is below the "
                    f"minimum threshold. Provided that you have either a monitoring "
                    f"service or a path finding service activated, your node is not going "
                    f"to be able to pay those services which may lead to denial of service or "
                    f"loss of funds."
                ),
                fg="red",
            )

        gevent.sleep(CHECK_RDN_MIN_DEPOSIT_INTERVAL)


def check_network_id(network_id, web3: Web3):  # pragma: no unittest
    """ Check periodically if the underlying ethereum client's network id has changed"""
    while True:
        current_id = int(web3.version.network)
        if network_id != current_id:
            raise RuntimeError(
                f"Raiden was running on network with id {network_id} and it detected "
                f"that the underlying ethereum client network id changed to {current_id}."
                f" Changing the underlying blockchain while the Raiden node is running "
                f"is not supported."
            )
        gevent.sleep(CHECK_NETWORK_ID_INTERVAL)


class AlarmTask(Runnable):
    """ Task to notify when a block is mined. """

    def __init__(self, chain):
        super().__init__()

        self.callbacks: List[Callable] = list()
        self.chain = chain
        self.chain_id = None
        self.known_block_number = None
        self._stop_event = None

        # TODO: Start with a larger sleep_time and decrease it as the
        # probability of a new block increases.
        self.sleep_time = 0.5

    def __repr__(self):
        return f"<{self.__class__.__name__} node:{to_checksum_address(self.chain.client.address)}>"

    def start(self):
        log.debug("Alarm task started", node=to_checksum_address(self.chain.node_address))
        self._stop_event = AsyncResult()
        super().start()

    def _run(self):  # pylint: disable=method-hidden
        self.greenlet.name = (
            f"AlarmTask._run node:{to_checksum_address(self.chain.client.address)}"
        )
        try:
            self.loop_until_stop()
        finally:
            self.callbacks = list()

    def is_primed(self):
        """True if the first_run has been called."""
        return bool(self.chain_id and self.known_block_number is not None)

    def register_callback(self, callback):
        """ Register a new callback.

        Note:
            The callback will be executed in the AlarmTask context and for
            this reason it should not block, otherwise we can miss block
            changes.
        """
        if not callable(callback):
            raise ValueError("callback is not a callable")

        self.callbacks.append(callback)

    def remove_callback(self, callback):
        """Remove callback from the list of callbacks if it exists"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def loop_until_stop(self):
        # The AlarmTask must have completed its first_run() before starting
        # the background greenlet.
        #
        # This is required because the first run will synchronize the node with
        # the blockchain since the last run.
        msg = "Only start the AlarmTask after it has been primed with the first_run"
        assert self.is_primed(), msg

        sleep_time = self.sleep_time
        while self._stop_event.wait(sleep_time) is not True:
            try:
                latest_block = self.chain.get_block(block_identifier="latest")
            except JSONDecodeError as e:
                raise EthNodeCommunicationError(str(e))

            self._maybe_run_callbacks(latest_block)

    def first_run(self, known_block_number):
        """ Blocking call to update the local state, if necessary. """
        assert self.callbacks, "callbacks not set"
        latest_block = self.chain.get_block(block_identifier="latest")

        log.debug(
            "Alarm task first run",
            known_block_number=known_block_number,
            latest_block_number=latest_block["number"],
            latest_gas_limit=latest_block["gasLimit"],
            latest_block_hash=to_hex(latest_block["hash"]),
        )

        self.known_block_number = known_block_number
        self.chain_id = self.chain.network_id
        self._maybe_run_callbacks(latest_block)

    def _maybe_run_callbacks(self, latest_block):
        """ Run the callbacks if there is at least one new block.

        The callbacks are executed only if there is a new block, otherwise the
        filters may try to poll for an inexisting block number and the Ethereum
        client can return an JSON-RPC error.
        """
        assert self.known_block_number is not None, "known_block_number not set"

        latest_block_number = latest_block["number"]
        missed_blocks = latest_block_number - self.known_block_number

        if missed_blocks < 0:
            log.critical(
                "Block number decreased",
                chain_id=self.chain_id,
                known_block_number=self.known_block_number,
                old_block_number=latest_block["number"],
                old_gas_limit=latest_block["gasLimit"],
                old_block_hash=to_hex(latest_block["hash"]),
            )
        elif missed_blocks > 0:
            log_details = dict(
                known_block_number=self.known_block_number,
                latest_block_number=latest_block_number,
                latest_block_hash=to_hex(latest_block["hash"]),
                latest_block_gas_limit=latest_block["gasLimit"],
            )
            if missed_blocks > 1:
                log_details["num_missed_blocks"] = missed_blocks - 1

            log.debug("Received new block", **log_details)

            remove = list()
            for callback in self.callbacks:
                result = callback(latest_block)
                if result is REMOVE_CALLBACK:
                    remove.append(callback)

            for callback in remove:
                self.callbacks.remove(callback)

            self.known_block_number = latest_block_number

    def stop(self):
        self._stop_event.set(True)
        log.debug("Alarm task stopped", node=to_checksum_address(self.chain.node_address))
        result = self.join()
        # Callbacks should be cleaned after join
        self.callbacks = []
        return result
