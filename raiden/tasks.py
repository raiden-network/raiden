import requests
import re
from pkg_resources import parse_version

import click
import gevent
from gevent.event import AsyncResult
import structlog


from raiden.exceptions import RaidenShuttingDown
from raiden.utils import get_system_spec

CHECK_VERSION_INTERVAL = 3 * 60 * 60
LATEST = 'https://api.github.com/repos/raiden-network/raiden/releases/latest'
RELEASE_PAGE = 'https://github.com/raiden-network/raiden/releases'
SECURITY_EXPRESSION = '\[CRITICAL UPDATE.*?\]'

REMOVE_CALLBACK = object()
log = structlog.get_logger(__name__)  # pylint: disable=invalid-name


def check_version():
    """Check every 3h for a new release"""
    app_version = parse_version(get_system_spec()['raiden'])
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


class AlarmTask(gevent.Greenlet):
    """ Task to notify when a block is mined. """

    def __init__(self, chain):
        super().__init__()

        # TODO: Start with a larger sleep_time and decrease it as the
        # probability of a new block increases.
        sleep_time = 0.5

        self.callbacks = list()
        self.chain = chain
        self.chain_id = None
        self.last_block_number = None
        self.stop_event = AsyncResult()
        self.sleep_time = sleep_time

    def _run(self):  # pylint: disable=method-hidden
        try:
            self.loop_until_stop()
        except RaidenShuttingDown:
            pass
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
        while self.stop_event.wait(sleep_time) is not True:
            last_block_number = self.last_block_number
            current_block = self.chain.block_number()

            if chain_id != self.chain.network_id:
                raise RuntimeError(
                    'Changing the underlying blockchain while the Raiden node is running '
                    'is not supported.',
                )

            if current_block != last_block_number:
                log.debug('new block', number=current_block)

                if current_block > last_block_number + 1:
                    missed_blocks = current_block - last_block_number - 1
                    log.info(
                        'missed blocks',
                        missed_blocks=missed_blocks,
                        current_block=current_block,
                    )

                self.run_callbacks(current_block, chain_id)

    def first_run(self):
        # callbacks must be executed during the first run to update the node state
        assert self.callbacks, 'callbacks not set'

        chain_id = self.chain.network_id
        current_block = self.chain.block_number()

        log.debug('starting at block number', current_block=current_block)

        self.run_callbacks(current_block, chain_id)
        self.chain_id = chain_id

    def run_callbacks(self, current_block, chain_id):
        remove = list()
        for callback in self.callbacks:
            result = callback(current_block, chain_id)
            if result is REMOVE_CALLBACK:
                remove.append(callback)

        for callback in remove:
            self.callbacks.remove(callback)

        self.last_block_number = current_block

    def stop_async(self):
        self.stop_event.set(True)
