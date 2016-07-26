import cStringIO
import sys
from logging import StreamHandler, Formatter
from collections import defaultdict

import gevent
from gevent.event import Event
import IPython
from IPython.lib.inputhook import inputhook_manager
from devp2p.service import BaseService
from ethereum.utils import denoms, decode_hex
from ethereum.slogging import getLogger
from ethereum._solidity import compile_file
from raiden.messages import Ping
from raiden.blockchain.abi import get_contract_path

from pyethapp.utils import bcolors as bc
from pyethapp.console_service import GeventInputHook, SigINTHandler

# ipython needs to accept "--gui gevent" option
IPython.core.shellapp.InteractiveShellApp.gui.values += ('gevent',)
inputhook_manager.register('gevent')(GeventInputHook)


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

        self.console_locals = dict(_raiden=Raiden(self.app),
                                   raiden=self.app.raiden,
                                   chain=self.app.raiden.chain,
                                   discovery=self.app.discovery,
                                   tools=ConsoleTools(self.app.raiden, self.app.discovery,
                                       self.app.config['settle_timeout'],
                                       self.app.config['reveal_timeout'],
                                       ),
                                   denoms=denoms,
                                   true=True,
                                   false=False,
                                   )

        # for k, v in self.app.script_globals.items():
        #     self.console_locals[k] = v

    def _run(self):
        self.interrupt.wait()
        print('\n' * 2)
        print("Entering Console" + bc.OKGREEN)
        print("Tip:" + bc.OKBLUE)
        # TODO: log help disabled for now
        # print("\tuse `{}lastlog(n){}` to see n lines of log-output. [default 10] ".format(
        #     bc.HEADER, bc.OKBLUE))
        # print("\tuse `{}lasterr(n){}` to see n lines of stderr.".format(bc.HEADER, bc.OKBLUE))
        print("\tuse `{}help(raiden){}` for help on interacting with the raiden network.".format(
            bc.HEADER, bc.OKBLUE))
        print("\tuse `{}raiden{}` to interact with the raiden service.".format(bc.HEADER, bc.OKBLUE))
        print("\tuse `{}chain{}` to interact with the blockchain.".format(bc.HEADER, bc.OKBLUE))
        print("\tuse `{}discovery{}` to find raiden nodes.".format(bc.HEADER, bc.OKBLUE))
        print("\tuse `{}tools{}` for creating tokens, registering assets etc...".format(bc.HEADER, bc.OKBLUE))
        print("\n" + bc.ENDC)

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
        self._discovery = discovery
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.assets = []
        self._ping_nonces = defaultdict(int)

    def create_token(self,
            initial_alloc=10 ** 6,
            name='raidentester',
            symbol='RDT',
            decimals=2,
            timeout=60,
            gasprice=denoms.shannon * 20):
        """Create a proxy for a new HumanStandardToken, that is initialized with
        Args:
            initial_alloc (int): amount of initial tokens.
            name (str): human readable token name.
            symbol (str): token shorthand symbol.
            decimals (int): decimal places
            kwargs (dict): will be passed to contract creation
        Returns:
            token_proxy: of the new token.
        """
        token_proxy = self._chain.client.deploy_solidity_contract(
            self._raiden.address, 'HumanStandardToken',
            compile_file(get_contract_path('HumanStandardToken.sol')),
            dict(),
            (initial_alloc, name, decimals, symbol),
            gasprice=gasprice,
            timeout=timeout)
        self.assets.append(token_proxy)
        return token_proxy

    def register_asset(self, token_address):
        """Register a token with the raiden asset manager.
        Args:
            token_address (string): a hex encoded token address.
        Returns:
            channel_manager: the channel_manager contract_proxy.
        """
        self._chain.default_registry.add_asset(token_address)
        channel_manager = self._chain.manager_by_asset(token_address.decode('hex'))
        self._raiden.register_channel_manager(channel_manager)
        return channel_manager

    def ping(self, peer, timeout=5.):
        """See, if a peer is discoverable and up.
        Args:
            peer (string): the hex-encoded (ethereum) address of the peer.
            timeout (float): how long to wait for the response.
        """
        address = decode_hex(peer)
        nonce = self._ping_nonces[peer]
        self._ping_nonces[peer] += 1
        msg = Ping(nonce)
        event = gevent.event.AsyncResult()
        self._raiden.send_and_wait(address, msg, timeout, event)
        return event

    def open_channel_with_funding(self, token_address, peer, amount,
                                  settle_timeout=None,
                                  reveal_timeout=None):
        """Convenience method to open a channel.
        Args:
            token_address (str): hex encoded address of the token for the channel.
            peer (str): hex encoded address of the channel peer.
            amount (int): amount of initial funding of the channel.
            settle_timeout (int): amount of blocks for the settle time (if None use app defaults).
            reveal_timeout (int): amount of blocks for the reveal time (if None use app defaults).
        Returns:
            netting_channel: the opened netting channel.
        """
        try:
            self._discovery.get(peer.decode('hex'))
        except KeyError:
            print("Error: peer {} not found in discovery".format(peer))
            return
        asset = self._raiden.chain.asset(token_address.decode('hex'))
        channel_manager = self._chain.manager_by_asset(token_address.decode('hex'))
        asset_manager = self._raiden.get_manager_by_asset_address(token_address.decode('hex'))
        netcontract_address = channel_manager.new_netting_channel(self._raiden.address,
                                                                peer.decode('hex'),
                                                                settle_timeout or self.settle_timeout)
        asset.approve(netcontract_address, amount)
        netting_channel = self._chain.netting_channel(netcontract_address)
        asset_manager.register_channel(netting_channel, reveal_timeout or self.reveal_timeout)
        netting_channel.deposit(self._raiden.address, amount)
        return netting_channel

    def deposit(self, token_address, peer, amount):
        """After your peer has called `open_channel_with_funding`, use this
        to deposit to the channel as well.
        Args:
            token_address (str): hex encoded address of the token.
            peer (str): hex encoded address of your peer.
            amount (int): amount of deposit.
        """
        asset = self._chain.asset(token_address.decode('hex'))
        assert asset
        asset_manager = self._raiden.get_manager_by_asset_address(token_address.decode('hex'))
        assert asset_manager
        netcontract_address = asset_manager.get_channel_by_partner_address(
            peer.decode('hex')).external_state.netting_channel.address

        assert len(netcontract_address)

        asset.approve(netcontract_address, amount)

        netting_channel = self._chain.netting_channel(netcontract_address)
        netting_channel.deposit(self._raiden.address, amount)
        return netting_channel
