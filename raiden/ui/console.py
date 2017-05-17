# -*- coding: utf-8 -*-
from __future__ import print_function

import cStringIO
import json
import sys
import time
from logging import StreamHandler, Formatter

import gevent
import IPython
from devp2p.service import BaseService
from ethereum.slogging import getLogger
from ethereum._solidity import compile_file
from ethereum.utils import denoms
from gevent.event import Event
from IPython.lib.inputhook import inputhook_manager
from pyethapp.utils import bcolors as bc
from pyethapp.jsonrpc import address_decoder, default_gasprice
from pyethapp.console_service import GeventInputHook, SigINTHandler

from raiden.api.python import RaidenAPI
from raiden.utils import events, get_contract_path, safe_address_decode

# ipython needs to accept "--gui gevent" option
IPython.core.shellapp.InteractiveShellApp.gui.values += ('gevent',)
inputhook_manager.register('gevent')(GeventInputHook)


def print_usage():
    print("\t{}use `{}raiden{}` to interact with the raiden service.".format(
        bc.OKBLUE, bc.HEADER, bc.OKBLUE))
    print("\tuse `{}chain{}` to interact with the blockchain.".format(bc.HEADER, bc.OKBLUE))
    print("\tuse `{}discovery{}` to find raiden nodes.".format(bc.HEADER, bc.OKBLUE))
    print("\tuse `{}tools{}` for convenience with tokens, channels, funding, ...".format(
        bc.HEADER, bc.OKBLUE))
    print("\tuse `{}denoms{}` for ether calculations".format(bc.HEADER, bc.OKBLUE))
    print("\tuse `{}lastlog(n){}` to see n lines of log-output. [default 10] ".format(
        bc.HEADER, bc.OKBLUE))
    print("\tuse `{}lasterr(n){}` to see n lines of stderr. [default 1]".format(
        bc.HEADER, bc.OKBLUE))
    print("\tuse `{}help(<topic>){}` for help on a specific topic.".format(bc.HEADER, bc.OKBLUE))
    print("\ttype `{}usage(){}` to see this help again.".format(bc.HEADER, bc.OKBLUE))
    print("\n" + bc.ENDC)


class Console(BaseService):

    """A service starting an interactive ipython session when receiving the
    SIGSTP signal (e.g. via keyboard shortcut CTRL-Z).
    """

    name = 'console'

    def __init__(self, app):
        super(Console, self).__init__(app)
        self.interrupt = Event()
        self.console_locals = {}
        if app.start_console:
            self.start()
            self.interrupt.set()
        else:
            SigINTHandler(self.interrupt)

    def _stop_app(self):
        try:
            self.app.stop()
        except gevent.GreenletExit:
            pass

    def start(self):
        # start console service
        super(Console, self).start()

        class Raiden(object):
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

    def _run(self):
        self.interrupt.wait()
        print('\n' * 2)
        print("Entering Console" + bc.OKGREEN)
        print("Tip:" + bc.OKBLUE)
        print_usage()

        # Remove handlers that log to stderr
        root = getLogger()
        for handler in root.handlers[:]:
            if isinstance(handler, StreamHandler) and handler.stream == sys.stderr:
                root.removeHandler(handler)

        stream = cStringIO.StringIO()
        handler = StreamHandler(stream=stream)
        handler.formatter = Formatter("%(levelname)s:%(name)s %(message)s")
        root.addHandler(handler)

        def lastlog(n=10, prefix=None, level=None):
            """Print the last `n` log lines to stdout.
            Use `prefix='p2p'` to filter for a specific logger.
            Use `level=INFO` to filter for a specific level.
            Level- and prefix-filtering are applied before tailing the log.
            """
            lines = (stream.getvalue().strip().split('\n') or [])
            if prefix:
                lines = filter(lambda line: line.split(':')[1].startswith(prefix), lines)
            if level:
                lines = filter(lambda line: line.split(':')[0] == level, lines)
            for line in lines[-n:]:
                print(line)

        self.console_locals['lastlog'] = lastlog

        err = cStringIO.StringIO()
        sys.stderr = err

        def lasterr(n=1):
            """Print the last `n` entries of stderr to stdout.
            """
            for line in (err.getvalue().strip().split('\n') or [])[-n:]:
                print(line)

        self.console_locals['lasterr'] = lasterr

        IPython.start_ipython(argv=['--gui', 'gevent'], user_ns=self.console_locals)
        self.interrupt.clear()

        sys.exit(0)


class ConsoleTools(object):
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
            gasprice=default_gasprice,
            auto_register=True):
        """Create a proxy for a new HumanStandardToken (ERC20), that is
        initialized with Args(below).
        Per default it will be registered with 'raiden'.

        Args:
            initial_alloc (int): amount of initial tokens.
            name (str): human readable token name.
            symbol (str): token shorthand symbol.
            decimals (int): decimal places.
            timeout (int): timeout in seconds for creation.
            gasprice (int): gasprice for the creation transaction.
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
            gasprice=gasprice,
            timeout=timeout)
        token_address_hex = token_proxy.address.encode('hex')
        if auto_register:
            self.register_token(token_address_hex)
        print("Successfully created {}the token '{}'.".format(
            'and registered ' if auto_register else ' ',
            name
        ))
        return token_address_hex

    def register_token(self, token_address_hex):
        """Register a token with the raiden token manager.
        Args:
            token_address_hex (string): a hex encoded token address.
        Returns:
            channel_manager: the channel_manager contract_proxy.
        """
        # Add the ERC20 token to the raiden registry
        token_address = safe_address_decode(token_address_hex)
        self._chain.default_registry.add_token(token_address)

        # Obtain the channel manager for the token
        channel_manager = self._chain.manager_by_token(token_address)

        # Register the channel manager with the raiden registry
        self._raiden.register_channel_manager(channel_manager.address)
        return channel_manager

    def ping(self, peer_address_hex, timeout=4):
        """
        See, if a peer is discoverable and up.
           Args:
                peer_address_hex (string): the hex-encoded (ethereum) address of the peer.
                timeout (int): The number of seconds to wait for the peer to
                               acknowledge our ping
        Returns:
            success (boolean): True if ping succeeded, False otherwise.
        """
        # Check, if peer is discoverable
        peer_address = address_decoder(peer_address_hex)
        try:
            self._discovery.get(peer_address)
        except KeyError:
            print("Error: peer {} not found in discovery".format(peer_address_hex))
            return False

        async_result = self._raiden.protocol.send_ping(peer_address)
        return async_result.wait(timeout) is not None

    def open_channel_with_funding(
            self,
            token_address_hex,
            peer_address_hex,
            amount,
            settle_timeout=None,
            reveal_timeout=None):
        """Convenience method to open a channel.
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
            print("Error: peer {} not found in discovery".format(peer_address_hex))
            return

        self._api.open(
            token_address,
            peer_address,
            settle_timeout=settle_timeout,
            reveal_timeout=reveal_timeout,
        )

        return self._api.deposit(token_address, peer_address, amount)

    def channel_stats_for(self, token_address_hex, peer_address_hex, pretty=False):
        """Collect information about sent and received transfers
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
        graph = self._raiden.channelgraphs[token_address]
        assert graph

        # Get the channel
        channel = graph.partneraddress_channel[peer_address]
        assert channel

        # Collect data
        stats = dict(
            transfers=dict(
                received=[t.transferred_amount for t in channel.received_transfers],
                sent=[t.transferred_amount for t in channel.sent_transfers],
            ),
            channel=(channel
                     if not pretty
                     else channel.external_state.netting_channel.address.encode('hex')),
            lifecycle=dict(
                opened_at=channel.external_state.opened_block or 'not yet',
                open=channel.isopen,
                closed_at=channel.external_state.closed_block or 'not yet',
                settled_at=channel.external_state.settled_block or 'not yet',
            ),
            funding=channel.external_state.netting_channel.detail(self._raiden.address),
            token=dict(
                our_balance=token.balance_of(self._raiden.address),
                partner_balance=token.balance_of(peer_address),
                name=token.proxy.name(),
                symbol=token.proxy.symbol(),
            ),
        )
        stats['funding']['our_address'] = stats['funding']['our_address'].encode('hex')
        stats['funding']['partner_address'] = stats['funding']['partner_address'].encode('hex')
        if not pretty:
            return stats
        else:
            print(json.dumps(stats, indent=2, sort_keys=True))

    def show_events_for(self, token_address_hex, peer_address_hex):
        """Find all EVM-EventLogs for a channel.
        Args:
            token_address_hex (string): hex encoded address of the token
            peer_address_hex (string): hex encoded address of the peer
        Returns:
            events (list)
        """
        token_address = safe_address_decode(token_address_hex)
        peer_address = safe_address_decode(peer_address_hex)

        graph = self._raiden.channelgraphs[token_address]
        assert graph

        channel = graph.partneraddress_channel[peer_address]
        netcontract_address = channel.external_state.netting_channel.address
        assert len(netcontract_address)

        netting_channel = self._chain.netting_channel(netcontract_address)
        return events.netting_channel_events(self._chain.client, netting_channel)

    def wait_for_contract(self, contract_address_hex, timeout=None):
        """Wait until a contract is mined
        Args:
            contract_address_hex (string): hex encoded address of the contract
            timeout (int): time to wait for the contract to get mined
        Returns:
            True if the contract got mined, false otherwise
        """
        contract_address = safe_address_decode(contract_address_hex)
        start_time = time.time()
        result = self._raiden.chain.client.call(
            'eth_getCode',
            contract_address,
            'latest',
        )

        current_time = time.time()
        while result == '0x':
            if timeout and start_time + timeout > current_time:
                return False

            result = self._raiden.chain.client.call(
                'eth_getCode',
                contract_address,
                'latest',
            )
            gevent.sleep(0.5)

            current_time = time.time()

        return result != '0x'
