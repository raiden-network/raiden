import cStringIO
import sys
from logging import StreamHandler, Formatter

import gevent
from gevent.event import Event
import IPython
from IPython.lib.inputhook import inputhook_manager
from devp2p.service import BaseService
from ethereum.utils import denoms
from ethereum.slogging import getLogger
from ethereum._solidity import compile_file

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
        #start console service
        super(Console, self).start()

        class Raiden(object):
            def __init__(self, app):
                self.app = app

        self.console_locals = dict(_raiden=Raiden(self.app),
                                   raiden=self.app.raiden,
                                   chain=self.app.raiden.chain,
                                   discovery=self.app.discovery,
                                   tools=ConsoleTools(self.app.raiden),
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
    def __init__(self, raiden_service):
        self.__chain = raiden_service.chain
        self.__raiden = raiden_service
        self.assets = []

    def create_token(self,
            initial_alloc=10 ** 6,
            name='raidentester',
            symbol='RDT',
            decimals=2):
        """Create a proxy for a new HumanStandardToken, that is initialized with
        :initial_alloc: int amount
        :name: str name
        :symbol: str symbol
        :decimals: int decimal places
        """
        token_proxy = self.__chain.client.deploy_solidity_contract(
            self.__raiden.address, 'HumanStandardToken',
            compile_file('raiden/smart_contracts/HumanStandardToken.sol'),
            dict(),
            (10 ** 6, 'raiden', 2, 'RD'),
            gasprice=denoms.shannon * 20,
            timeout=5000)
        self.assets.append(token_proxy)
        return token_proxy

    def register_asset(self, token_proxy):
        """Register a token with the asset manager.
        :return: the channel_manager_proxy
        """
        self.__chain.default_registry.add_asset(token_proxy.address.encode('hex'))
        manager = self.__chain.manager_by_asset(token_proxy.address)
        self.__raiden.register_channel_manager(manager)
        return manager
