# -*- coding: utf-8 -*-
from binascii import hexlify
import io
import errno
import json
import os
import select
import signal
import sys
import time
from logging import StreamHandler, Formatter

from ethereum.slogging import getLogger
from ethereum.tools._solidity import compile_file
from ethereum.utils import denoms
import gevent
from gevent.event import Event
from gevent import Greenlet
import IPython
from IPython.lib.inputhook import inputhook_manager, stdin_ready

from raiden.api.python import RaidenAPI
from raiden.utils import events, get_contract_path, safe_address_decode

ENTER_CONSOLE_TIMEOUT = 3
GUI_GEVENT = 'gevent'

# ansi escape code for typesetting
HEADER = '\033[95m'
OKBLUE = '\033[94m'
OKGREEN = '\033[92m'
WARNING = '\033[91m'
FAIL = '\033[91m'
ENDC = '\033[0m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'

# ipython needs to accept "--gui gevent" option
IPython.core.shellapp.InteractiveShellApp.gui.values += ('gevent',)


def print_usage():
    print("\t{}use `{}raiden{}` to interact with the raiden service.".format(
        OKBLUE, HEADER, OKBLUE))
    print("\tuse `{}chain{}` to interact with the blockchain.".format(HEADER, OKBLUE))
    print("\tuse `{}discovery{}` to find raiden nodes.".format(HEADER, OKBLUE))
    print("\tuse `{}tools{}` for convenience with tokens, channels, funding, ...".format(
        HEADER, OKBLUE))
    print("\tuse `{}denoms{}` for ether calculations".format(HEADER, OKBLUE))
    print("\tuse `{}lastlog(n){}` to see n lines of log-output. [default 10] ".format(
        HEADER, OKBLUE))
    print("\tuse `{}lasterr(n){}` to see n lines of stderr. [default 1]".format(
        HEADER, OKBLUE))
    print("\tuse `{}help(<topic>){}` for help on a specific topic.".format(HEADER, OKBLUE))
    print("\ttype `{}usage(){}` to see this help again.".format(HEADER, OKBLUE))
    print("\n" + ENDC)


def inputhook_gevent():
    while not stdin_ready():
        gevent.sleep(0.05)
    return 0


@inputhook_manager.register('gevent')
class GeventInputHook:

    def __init__(self, manager):
        self.manager = manager
        self._current_gui = GUI_GEVENT

    def enable(self, app=None):
        """ Enable event loop integration with gevent.

        Args:
            app: Ignored, it's only a placeholder to keep the call signature of all
                gui activation methods consistent, which simplifies the logic of
                supporting magics.

        Notes:
            This methods sets the PyOS_InputHook for gevent, which allows
            gevent greenlets to run in the background while interactively using
            IPython.
        """
        self.manager.set_inputhook(inputhook_gevent)
        self._current_gui = GUI_GEVENT
        return app

    def disable(self):
        """ Disable event loop integration with gevent.

        This merely sets PyOS_InputHook to NULL.
        """
        self.manager.clear_inputhook()


class SigINTHandler:

    def __init__(self, event):
        self.event = event
        self.installed = None
        self.installed_force = None
        self.install_handler()

    def install_handler(self):
        if self.installed_force:
            self.installed_force.cancel()
            self.installed_force = None
        self.installed = gevent.signal(signal.SIGINT, self.handle_int)

    def install_handler_force(self):
        if self.installed:
            self.installed.cancel()
            self.installed = None
        self.installed_force = gevent.signal(signal.SIGINT, self.handle_force)

    def handle_int(self):
        self.install_handler_force()

        gevent.spawn(self._confirm_enter_console)

    def handle_force(self):  # pylint: disable=no-self-use
        """ User pressed ^C a second time. Send SIGTERM to ourself. """
        os.kill(os.getpid(), signal.SIGTERM)

    def _confirm_enter_console(self):
        start = time.time()
        sys.stdout.write('\n')
        enter_console = False
        while time.time() - start < ENTER_CONSOLE_TIMEOUT:
            prompt = (
                '\r{}{}Hit [ENTER], to launch console; [Ctrl+C] again to quit! [{:1.0f}s]{}'
            ).format(
                OKGREEN,
                BOLD,
                ENTER_CONSOLE_TIMEOUT - (time.time() - start),
                ENDC
            )

            sys.stdout.write(prompt)
            sys.stdout.flush()

            try:
                r, _, _ = select.select([sys.stdin], [], [], .5)
            except select.error as ex:
                sys.stdout.write('\n')
                # "Interrupted system call" means the user pressed ^C again
                if ex.args[0] == errno.EINTR:
                    self.handle_force()
                    return
                else:
                    raise
            if r:
                sys.stdin.readline()
                enter_console = True
                break
        if enter_console:
            sys.stdout.write('\n')
            self.installed_force.cancel()
            self.event.set()
        else:
            msg = '\n{}{}No answer after {}s. Resuming.{}\n'.format(
                WARNING,
                BOLD,
                ENTER_CONSOLE_TIMEOUT,
                ENDC,
            )

            sys.stdout.write(msg)
            sys.stdout.flush()
            # Restore regular handler
            self.install_handler()


class BaseService(Greenlet):
    def __init__(self, app):
        Greenlet.__init__(self)
        self.is_stopped = False
        self.app = app
        self.config = app.config

    def start(self):
        self.is_stopped = False
        Greenlet.start(self)

    def stop(self):
        self.is_stopped = True
        Greenlet.kill(self)


class Console(BaseService):
    """ A service starting an interactive ipython session when receiving the
    SIGSTP signal (e.g. via keyboard shortcut CTRL-Z).
    """

    def __init__(self, app):
        super().__init__(app)
        self.interrupt = Event()
        self.console_locals = {}
        if app.start_console:
            self.start()
            self.interrupt.set()
        else:
            SigINTHandler(self.interrupt)

    def start(self):
        # start console service
        super().start()

        class Raiden:
            def __init__(self, app):
                self.app = app

        self.console_locals = dict(
            _raiden=Raiden(self.app),
            raiden=self.app.raiden,
            chain=self.app.raiden.chain,
            discovery=self.app.discovery,
            tools=ConsoleTools(
                self.app.raiden,
                self.app.discovery,
                self.app.config['settle_timeout'],
                self.app.config['reveal_timeout'],
            ),
            denoms=denoms,
            true=True,
            false=False,
            usage=print_usage,
        )

    def _run(self):  # pylint: disable=method-hidden
        self.interrupt.wait()
        print('\n' * 2)
        print('Entering Console' + OKGREEN)
        print('Tip:' + OKBLUE)
        print_usage()

        # Remove handlers that log to stderr
        root = getLogger()
        for handler in root.handlers[:]:
            if isinstance(handler, StreamHandler) and handler.stream == sys.stderr:
                root.removeHandler(handler)

        stream = io.StringIO()
        handler = StreamHandler(stream=stream)
        handler.formatter = Formatter(u'%(levelname)s:%(name)s %(message)s')
        root.addHandler(handler)

        def lastlog(n=10, prefix=None, level=None):
            """ Print the last `n` log lines to stdout.
            Use `prefix='p2p'` to filter for a specific logger.
            Use `level=INFO` to filter for a specific level.
            Level- and prefix-filtering are applied before tailing the log.
            """
            lines = (stream.getvalue().strip().split('\n') or [])
            if prefix:
                lines = [
                    line
                    for line in lines
                    if line.split(':')[1].startswith(prefix)
                ]
            if level:
                lines = [
                    line
                    for line in lines
                    if line.split(':')[0] == level
                ]
            for line in lines[-n:]:
                print(line)

        self.console_locals['lastlog'] = lastlog

        err = io.StringIO()
        sys.stderr = err

        def lasterr(n=1):
            """ Print the last `n` entries of stderr to stdout. """
            for line in (err.getvalue().strip().split('\n') or [])[-n:]:
                print(line)

        self.console_locals['lasterr'] = lasterr

        IPython.start_ipython(argv=['--gui', 'gevent'], user_ns=self.console_locals)
        self.interrupt.clear()

        sys.exit(0)


class ConsoleTools:
    def __init__(self, raiden_service, discovery, settle_timeout, reveal_timeout):
        self._chain = raiden_service.chain
        self._raiden = raiden_service
        self._api = RaidenAPI(raiden_service)
        self._discovery = discovery
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.deposit = self._api.deposit

    def create_token(
            self,
            initial_alloc=10 ** 6,
            name='raidentester',
            symbol='RDT',
            decimals=2,
            timeout=60,
            auto_register=True):
        """ Create a proxy for a new HumanStandardToken (ERC20), that is
        initialized with Args(below).
        Per default it will be registered with 'raiden'.

        Args:
            initial_alloc (int): amount of initial tokens.
            name (str): human readable token name.
            symbol (str): token shorthand symbol.
            decimals (int): decimal places.
            timeout (int): timeout in seconds for creation.
            auto_register (boolean): if True(default), automatically register
                the token with raiden.

        Returns:
            token_address_hex: the hex encoded address of the new token/token.
        """
        contract_path = get_contract_path('HumanStandardToken.sol')
        # Deploy a new ERC20 token
        token_proxy = self._chain.client.deploy_solidity_contract(
            self._raiden.address, 'HumanStandardToken',
            compile_file(contract_path),
            dict(),
            (initial_alloc, name, decimals, symbol),
            contract_path=contract_path,
            timeout=timeout)
        token_address_hex = hexlify(token_proxy.contract_address)
        if auto_register:
            self.register_token(token_address_hex)
        print("Successfully created {}the token '{}'.".format(
            'and registered ' if auto_register else ' ',
            name
        ))
        return token_address_hex

    def register_token(self, token_address_hex):
        """ Register a token with the raiden token manager.

        Args:
            token_address_hex (string): a hex encoded token address.

        Returns:
            channel_manager: the channel_manager contract_proxy.
        """
        # Add the ERC20 token to the raiden registry
        token_address = safe_address_decode(token_address_hex)
        self._raiden.default_registry.add_token(token_address)

        # Obtain the channel manager for the token
        channel_manager = self._raiden.default_registry.manager_by_token(token_address)

        # Register the channel manager with the raiden registry
        self._raiden.register_channel_manager(channel_manager.address)
        return channel_manager

    def open_channel_with_funding(
            self,
            token_address_hex,
            peer_address_hex,
            amount,
            settle_timeout=None,
            reveal_timeout=None):
        """ Convenience method to open a channel.

        Args:
            token_address_hex (str): hex encoded address of the token for the channel.
            peer_address_hex (str): hex encoded address of the channel peer.
            amount (int): amount of initial funding of the channel.
            settle_timeout (int): amount of blocks for the settle time (if None use app defaults).
            reveal_timeout (int): amount of blocks for the reveal time (if None use app defaults).

        Return:
            netting_channel: the (newly opened) netting channel object.
        """
        # Check, if peer is discoverable
        peer_address = safe_address_decode(peer_address_hex)
        token_address = safe_address_decode(token_address_hex)
        try:
            self._discovery.get(peer_address)
        except KeyError:
            print('Error: peer {} not found in discovery'.format(peer_address_hex))
            return

        self._api.open(
            token_address,
            peer_address,
            settle_timeout=settle_timeout,
            reveal_timeout=reveal_timeout,
        )

        return self._api.deposit(token_address, peer_address, amount)

    def channel_stats_for(self, token_address_hex, peer_address_hex, pretty=False):
        """ Collect information about sent and received transfers
        between yourself and your peer for the given token.

        Args:
            token_address_hex (string): hex encoded address of the token
            peer_address_hex (string): hex encoded address of the peer
            pretty (boolean): if True, print a json representation instead of returning a dict

        Returns:
            stats (dict): collected stats for the channel or None if pretty

        """
        peer_address = safe_address_decode(peer_address_hex)
        token_address = safe_address_decode(token_address_hex)

        # Get the token
        token = self._chain.token(token_address)

        # Obtain the token manager
        graph = self._raiden.token_to_channelgraph[token_address]
        assert graph

        # Get the channel
        channel = graph.partneraddress_to_channel[peer_address]
        assert channel

        # Collect data
        stats = dict(
            transfers=dict(
                received=[t.transferred_amount for t in channel.received_transfers],
                sent=[t.transferred_amount for t in channel.sent_transfers],
            ),
            channel=(channel
                     if not pretty
                     else hexlify(channel.external_state.netting_channel.address)),
            lifecycle=dict(
                opened_at=channel.external_state.opened_block or 'not yet',
                can_transfer=channel.can_transfer,
                closed_at=channel.external_state.closed_block or 'not yet',
                settled_at=channel.external_state.settled_block or 'not yet',
            ),
            funding=channel.external_state.netting_channel.detail(),
            token=dict(
                our_balance=token.balance_of(self._raiden.address),
                partner_balance=token.balance_of(peer_address),
                name=token.proxy.name(),
                symbol=token.proxy.symbol(),
            ),
        )
        stats['funding']['our_address'] = hexlify(stats['funding']['our_address'])
        stats['funding']['partner_address'] = hexlify(stats['funding']['partner_address'])
        if not pretty:
            return stats
        else:
            print(json.dumps(stats, indent=2, sort_keys=True))

    def show_events_for(self, token_address_hex, peer_address_hex):
        """ Find all EVM-EventLogs for a channel.

        Args:
            token_address_hex (string): hex encoded address of the token
            peer_address_hex (string): hex encoded address of the peer

        Returns:
            events (list)
        """
        token_address = safe_address_decode(token_address_hex)
        peer_address = safe_address_decode(peer_address_hex)

        graph = self._raiden.token_to_channelgraph[token_address]
        assert graph

        channel = graph.partneraddress_to_channel[peer_address]
        netcontract_address = channel.external_state.netting_channel.address
        assert netcontract_address

        netting_channel = self._chain.netting_channel(netcontract_address)
        return events.netting_channel_events(self._chain.client, netting_channel)

    def wait_for_contract(self, contract_address_hex, timeout=None):
        """ Wait until a contract is mined

        Args:
            contract_address_hex (string): hex encoded address of the contract
            timeout (int): time to wait for the contract to get mined

        Returns:
            True if the contract got mined, false otherwise
        """
        contract_address = safe_address_decode(contract_address_hex)
        start_time = time.time()
        result = self._raiden.chain.client.eth_getCode(contract_address)

        current_time = time.time()
        while len(result) == 0:
            if timeout and start_time + timeout > current_time:
                return False

            result = self._raiden.chain.client.eth_getCode(contract_address)
            gevent.sleep(0.5)

            current_time = time.time()

        return len(result) > 0
