import re

import click
import gevent
import requests
import structlog
from gevent.event import AsyncResult
from pkg_resources import parse_version
from web3 import Web3

from raiden.utils import gas_reserve
from raiden.utils.runnable import Runnable

CHECK_VERSION_INTERVAL = 3 * 60 * 60
CHECK_GAS_RESERVE_INTERVAL = 60 * 60
LATEST = 'https://api.github.com/repos/raiden-network/raiden/releases/latest'
RELEASE_PAGE = 'https://github.com/raiden-network/raiden/releases'
SECURITY_EXPRESSION = r'\[CRITICAL UPDATE.*?\]'

REMOVE_CALLBACK = object()
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def check_version(current_version: str):
    """ Check periodically for a new release """
    app_version = parse_version(current_version)
    while True:
        try:
            content = requests.get(LATEST).json()
            # getting the latest release version
            latest_release = parse_version(content['tag_name'])
            security_message = re.search(SECURITY_EXPRESSION, content['body'])
            if security_message:
                click.secho(security_message.group(0), fg='red')
            # comparing it to the user's application
            if app_version < latest_release:
                msg = "You're running version {}. The latest version is {}".format(
                    app_version,
                    latest_release,
                )
                click.secho(msg, fg='red')
                click.secho("It's time to update! Releases: {}".format(RELEASE_PAGE), fg='red')
        except requests.exceptions.HTTPError as herr:
            click.secho('Error while checking for version', fg='red')
            print(herr)
        except ValueError as verr:
            click.secho('Error while checking the version', fg='red')
            print(verr)
        finally:
            # repeat the process once every 3h
            gevent.sleep(CHECK_VERSION_INTERVAL)


def check_gas_reserve(raiden):
    """ Check periodically for gas reserve in the account """
    while True:
        has_enough_balance, estimated_required_balance = gas_reserve.has_enough_gas_reserve(
            raiden,
            channels_to_open=0,
        )
        estimated_required_balance_eth = Web3.fromWei(estimated_required_balance, 'ether')

        if not has_enough_balance:
            log.info('Missing gas reserve', required_wei=estimated_required_balance)
            click.secho(
                (
                    'WARNING\n'
                    "Your account's balance is below the estimated gas reserve of "
                    f'{estimated_required_balance_eth} eth. This may lead to a loss of '
                    'of funds because your account will be unable to perform on-chain '
                    'transactions. Please add funds to your account as soon as possible.'
                ),
                fg='red',
            )

        gevent.sleep(CHECK_GAS_RESERVE_INTERVAL)


class AlarmTask(Runnable):
    """ Task to notify when a block is mined. """

    def __init__(self, chain):
        super().__init__()

        self.callbacks = list()
        self.chain = chain
        self.chain_id = None
        self.last_block_number = None
        self._stop_event = AsyncResult()

        # TODO: Start with a larger sleep_time and decrease it as the
        # probability of a new block increases.
        self.sleep_time = 0.5

    def _run(self):  # pylint: disable=method-hidden
        try:
            self.loop_until_stop()
        finally:
            self.callbacks = list()

    def register_callback(self, callback):
        """ Register a new callback.

        Note:
            The callback will be executed in the AlarmTask context and for
            this reason it should not block, otherwise we can miss block
            changes.
        """
        if not callable(callback):
            raise ValueError('callback is not a callable')

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
        assert self.chain_id, 'chain_id not set'
        assert self.last_block_number, 'last_block_number not set'

        chain_id = self.chain_id

        sleep_time = self.sleep_time
        while self._stop_event.wait(sleep_time) is not True:
            last_block_number = self.last_block_number
            latest_block = self.chain.get_block(block_identifier='latest')
            latest_block_number = latest_block['number']

            if chain_id != self.chain.network_id:
                raise RuntimeError(
                    'Changing the underlying blockchain while the Raiden node is running '
                    'is not supported.',
                )

            if latest_block_number != last_block_number:
                log.debug(
                    'new block',
                    number=latest_block_number,
                    gas_limit=latest_block['gasLimit'],
                    block_hash=latest_block['hash'],
                )

                if latest_block_number > last_block_number + 1:
                    missed_blocks = latest_block_number - last_block_number - 1
                    log.info(
                        'missed blocks',
                        missed_blocks=missed_blocks,
                        latest_block=latest_block,
                    )

                self._run_callbacks(latest_block)

    def first_run(self):
        # callbacks must be executed during the first run to update the node state
        assert self.callbacks, 'callbacks not set'

        chain_id = self.chain.network_id
        latest_block = self.chain.get_block(block_identifier='latest')

        log.debug(
            'starting at block number',
            number=latest_block['number'],
            gas_limit=latest_block['gasLimit'],
            block_hash=latest_block['hash'],
        )

        self._run_callbacks(latest_block)
        self.chain_id = chain_id

    def _run_callbacks(self, latest_block):
        remove = list()
        for callback in self.callbacks:
            result = callback(latest_block)
            if result is REMOVE_CALLBACK:
                remove.append(callback)

        for callback in remove:
            self.callbacks.remove(callback)

        self.last_block_number = latest_block['number']

    def stop(self):
        self._stop_event.set(True)
        return self.join()
