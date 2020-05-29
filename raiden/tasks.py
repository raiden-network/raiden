import re
from typing import TYPE_CHECKING

import click
import gevent
import requests
import structlog
from eth_utils import to_hex
from gevent.event import AsyncResult
from pkg_resources import parse_version
from web3 import Web3
from web3.types import BlockData

from raiden.constants import (
    BLOCK_ID_LATEST,
    CHECK_GAS_RESERVE_INTERVAL,
    CHECK_NETWORK_ID_INTERVAL,
    CHECK_RDN_MIN_DEPOSIT_INTERVAL,
    CHECK_VERSION_INTERVAL,
    LATEST,
    RELEASE_PAGE,
    SECURITY_EXPRESSION,
)
from raiden.network.proxies.proxy_manager import ProxyManager
from raiden.network.proxies.user_deposit import UserDeposit
from raiden.settings import MIN_REI_THRESHOLD
from raiden.utils import gas_reserve
from raiden.utils.formatting import to_checksum_address
from raiden.utils.runnable import Runnable
from raiden.utils.transfers import to_rdn
from raiden.utils.typing import Any, BlockNumber, Callable, ChainID, List, Optional, Tuple

if TYPE_CHECKING:
    from raiden.raiden_service import RaidenService

REMOVE_CALLBACK = object()
log = structlog.get_logger(__name__)


def _do_check_version(current_version: Tuple[str, ...]) -> bool:
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


def check_version(current_version: str) -> None:  # pragma: no unittest
    """ Check periodically for a new release """
    app_version = parse_version(current_version)
    while True:
        try:
            _do_check_version(app_version)
        except (requests.exceptions.HTTPError, ValueError) as err:
            click.secho("Error while checking for version", fg="red")
            print(err)

        # repeat the process once every 3h
        gevent.sleep(CHECK_VERSION_INTERVAL)


def check_gas_reserve(raiden: "RaidenService") -> None:  # pragma: no unittest
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


def check_rdn_deposits(
    raiden: "RaidenService", user_deposit_proxy: UserDeposit
) -> None:  # pragma: no unittest
    """ Check periodically for RDN deposits in the user-deposits contract """
    while True:
        rei_balance = user_deposit_proxy.effective_balance(raiden.address, BLOCK_ID_LATEST)
        rdn_balance = to_rdn(rei_balance)
        if rei_balance < MIN_REI_THRESHOLD:
            click.secho(
                (
                    f"WARNING\n"
                    f"Your account's RDN balance deposited in the UserDepositContract of "
                    f"{rdn_balance} is below the minimum threshold {to_rdn(MIN_REI_THRESHOLD)}. "
                    f"Provided that you have either a monitoring service or a path "
                    f"finding service activated, your node is not going to be able to "
                    f"pay those services which may lead to denial of service or loss of funds."
                ),
                fg="red",
            )

        gevent.sleep(CHECK_RDN_MIN_DEPOSIT_INTERVAL)


def check_network_id(network_id: ChainID, web3: Web3) -> None:  # pragma: no unittest
    """ Check periodically if the underlying ethereum client's network id has changed"""
    while True:
        current_id = web3.eth.chainId
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

    def __init__(self, proxy_manager: ProxyManager, sleep_time: float) -> None:
        super().__init__()

        self.callbacks: List[Callable] = list()
        self.proxy_manager = proxy_manager
        self.rpc_client = proxy_manager.client

        self.known_block_number: Optional[BlockNumber] = None
        self._stop_event: Optional[AsyncResult] = None

        # TODO: Start with a larger sleep_time and decrease it as the
        # probability of a new block increases.
        self.sleep_time = sleep_time

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} node:" f"{to_checksum_address(self.rpc_client.address)}>"
        )

    def start(self) -> None:
        log.debug("Alarm task started", node=to_checksum_address(self.rpc_client.address))
        self._stop_event = AsyncResult()
        super().start()

    def _run(self, *args: Any, **kwargs: Any) -> None:  # pylint: disable=method-hidden
        self.greenlet.name = f"AlarmTask._run node:{to_checksum_address(self.rpc_client.address)}"
        try:
            self.loop_until_stop()
        finally:
            self.callbacks = list()

    def register_callback(self, callback: Callable) -> None:
        """ Register a new callback.

        Note:
            The callback will be executed in the AlarmTask context and for
            this reason it should not block, otherwise we can miss block
            changes.
        """
        if not callable(callback):
            raise ValueError("callback is not a callable")

        self.callbacks.append(callback)

    def remove_callback(self, callback: Callable) -> None:
        """Remove callback from the list of callbacks if it exists"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)

    def loop_until_stop(self) -> None:
        sleep_time = self.sleep_time
        while self._stop_event and self._stop_event.wait(sleep_time) is not True:
            latest_block = self.rpc_client.get_block(block_identifier=BLOCK_ID_LATEST)

            self._maybe_run_callbacks(latest_block)

    def _maybe_run_callbacks(self, latest_block: BlockData) -> None:
        """ Run the callbacks if there is at least one new block.

        The callbacks are executed only if there is a new block, otherwise the
        filters may try to poll for an inexisting block number and the Ethereum
        client can return an JSON-RPC error.
        """
        latest_block_number = latest_block["number"]

        # First run, set the block and run the callbacks
        if self.known_block_number is None:
            self.known_block_number = latest_block_number
            missed_blocks = 1
        else:
            missed_blocks = latest_block_number - self.known_block_number

        if missed_blocks < 0:
            log.critical(
                "Block number decreased",
                chain_id=self.rpc_client.chain_id,
                known_block_number=self.known_block_number,
                old_block_number=latest_block["number"],
                old_gas_limit=latest_block["gasLimit"],
                old_block_hash=to_hex(latest_block["hash"]),
                node=to_checksum_address(self.rpc_client.address),
            )
        elif missed_blocks > 0:
            log_details = dict(
                known_block_number=self.known_block_number,
                latest_block_number=latest_block_number,
                latest_block_hash=to_hex(latest_block["hash"]),
                latest_block_gas_limit=latest_block["gasLimit"],
                node=to_checksum_address(self.rpc_client.address),
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

    def stop(self) -> Any:
        if self._stop_event:
            self._stop_event.set(True)
        log.debug("Alarm task stopped", node=to_checksum_address(self.rpc_client.address))
        result = self.greenlet.join()
        # Callbacks should be cleaned after join
        self.callbacks = []
        return result
