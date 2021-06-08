import io
import logging
import sys
import time

import gevent
import IPython
import nest_asyncio
from eth_utils import denoms, to_canonical_address

from raiden import waiting
from raiden.api.python import RaidenAPI
from raiden.constants import BLOCK_ID_LATEST, UINT256_MAX
from raiden.network.proxies.token_network import TokenNetwork
from raiden.raiden_service import RaidenService
from raiden.settings import DEFAULT_RETRY_TIMEOUT
from raiden.utils.formatting import to_hex_address
from raiden.utils.typing import (
    Address,
    AddressHex,
    Any,
    BlockTimeout,
    Dict,
    NetworkTimeout,
    TokenAddress,
    TokenAmount,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.constants import CONTRACT_HUMAN_STANDARD_TOKEN

GUI_GEVENT = "gevent"

# ansi escape code for typesetting
HEADER = "\033[95m"
OKBLUE = "\033[94m"
OKGREEN = "\033[92m"
ENDC = "\033[0m"


def print_usage() -> None:
    print(f"\tuse `{HEADER}app{OKBLUE}` to interact with the top level Raiden API.")
    print(f"\t{OKBLUE}use `{HEADER}raiden{OKBLUE}` to interact with the raiden service.")
    print(
        "\tuse `{}tools{}` for convenience with tokens, channels, funding, ...".format(
            HEADER, OKBLUE
        )
    )
    print(f"\tuse `{HEADER}denoms{OKBLUE}` for ether calculations")
    print(f"\tuse `{HEADER}lastlog(n){OKBLUE}` to see n lines of log-output. [default 10] ")
    print(f"\tuse `{HEADER}lasterr(n){OKBLUE}` to see n lines of stderr. [default 1]")
    print(f"\tuse `{HEADER}help(<topic>){OKBLUE}` for help on a specific topic.")
    print(f"\ttype `{HEADER}usage(){OKBLUE}` to see this help again.")
    print("\n" + ENDC)


class Console(gevent.Greenlet):
    """A service starting an interactive ipython session when receiving the
    SIGSTP signal (e.g. via keyboard shortcut CTRL-Z).
    """

    def __init__(self, raiden_service: RaidenService) -> None:
        super().__init__()
        self.raiden_service = raiden_service
        self.console_locals: Dict[str, Any] = {}

    def _run(self) -> None:  # pylint: disable=method-hidden
        # Remove handlers that log to stderr
        root = logging.getLogger()
        for handler in root.handlers[:]:
            if isinstance(handler, logging.StreamHandler) and handler.stream == sys.stderr:
                root.removeHandler(handler)

        stream = io.StringIO()
        handler = logging.StreamHandler(stream=stream)
        handler.formatter = logging.Formatter("%(levelname)s:%(name)s %(message)s")
        root.addHandler(handler)
        err = io.StringIO()
        sys.stderr = err

        def lastlog(n: int = 10, prefix: str = None, level: str = None) -> None:
            """Print the last `n` log lines to stdout.
            Use `prefix='p2p'` to filter for a specific logger.
            Use `level=INFO` to filter for a specific level.
            Level- and prefix-filtering are applied before tailing the log.
            """
            lines = stream.getvalue().strip().split("\n") or []
            if prefix:
                lines = [line for line in lines if line.split(":")[1].startswith(prefix)]
            if level:
                lines = [line for line in lines if line.split(":")[0] == level]
            for line in lines[-n:]:
                print(line)

        def lasterr(n: int = 1) -> None:
            """Print the last `n` entries of stderr to stdout."""
            for line in (err.getvalue().strip().split("\n") or [])[-n:]:
                print(line)

        tools = ConsoleTools(self.raiden_service)

        self.console_locals = {
            "raiden": self.raiden_service,
            "denoms": denoms,
            "proxy_manager": self.raiden_service.proxy_manager,
            "tools": tools,
            "lasterr": lasterr,
            "lastlog": lastlog,
            "usage": print_usage,
        }

        print("\n" * 2)
        print("Entering Console" + OKGREEN)
        print("Tip:" + OKBLUE)
        print_usage()
        nest_asyncio.apply()
        IPython.start_ipython(argv=[], user_ns=self.console_locals)

        sys.exit(0)


class ConsoleTools:
    """Some functions to make working in the console easier."""

    def __init__(self, raiden_service: RaidenService) -> None:
        self._raiden = raiden_service
        self._api = RaidenAPI(raiden_service)

    def create_token(
        self,
        registry_address_hex: AddressHex,
        initial_alloc: int = 10 ** 6,
        name: str = "raidentester",
        symbol: str = "RDT",
        decimals: int = 2,
        timeout: int = 60,
        auto_register: bool = True,
    ) -> AddressHex:
        """Create a proxy for a new HumanStandardToken (ERC20), that is
        initialized with Args(below).
        Per default it will be registered with 'raiden'.

        Args:
            registry_address_hex: a hex encoded registry address.
            initial_alloc: amount of initial tokens.
            name: human readable token name.
            symbol: token shorthand symbol.
            decimals: decimal places.
            timeout: timeout in seconds for creation.
            auto_register: if True(default), automatically register
                the token with raiden.

        Returns:
            token_address_hex: the hex encoded address of the new token/token.
        """
        with gevent.Timeout(timeout):
            contract_proxy, _ = self._raiden.rpc_client.deploy_single_contract(
                contract_name=CONTRACT_HUMAN_STANDARD_TOKEN,
                contract=self._raiden.contract_manager.get_contract(CONTRACT_HUMAN_STANDARD_TOKEN),
                constructor_parameters=(initial_alloc, name, decimals, symbol),
            )
            token_address = Address(to_canonical_address(contract_proxy.address))

        token_address_hex = to_hex_address(token_address)
        if auto_register:
            self.register_token(registry_address_hex, token_address_hex)

        print(
            "Successfully created {}the token '{}'.".format(
                "and registered " if auto_register else "", name
            )
        )
        return token_address_hex

    def register_token(
        self,
        registry_address_hex: AddressHex,
        token_address_hex: AddressHex,
        retry_timeout: NetworkTimeout = DEFAULT_RETRY_TIMEOUT,
    ) -> TokenNetwork:
        """Register a token with the raiden token manager.

        Args:
            registry_address_hex: a hex encoded registry address.
            token_address_hex: a hex encoded token address.
            retry_timeout: the retry timeout

        Returns:
            The token network proxy.
        """
        registry_address = TokenNetworkRegistryAddress(to_canonical_address(registry_address_hex))
        token_address = TokenAddress(to_canonical_address(token_address_hex))

        registry = self._raiden.proxy_manager.token_network_registry(
            registry_address, BLOCK_ID_LATEST
        )

        _, token_network_address = registry.add_token(
            token_address=token_address,
            channel_participant_deposit_limit=TokenAmount(UINT256_MAX),
            token_network_deposit_limit=TokenAmount(UINT256_MAX),
            given_block_identifier=BLOCK_ID_LATEST,
        )
        waiting.wait_for_token_network(
            self._raiden, registry.address, token_address, retry_timeout
        )

        return self._raiden.proxy_manager.token_network(token_network_address, BLOCK_ID_LATEST)

    def open_channel_with_funding(
        self,
        registry_address_hex: AddressHex,
        token_address_hex: AddressHex,
        peer_address_hex: AddressHex,
        total_deposit: TokenAmount,
        settle_timeout: BlockTimeout = None,
    ) -> None:
        """Convenience method to open a channel.

        Args:
            registry_address_hex: hex encoded address of the registry for the channel.
            token_address_hex: hex encoded address of the token for the channel.
            peer_address_hex: hex encoded address of the channel peer.
            total_deposit: amount of total funding for the channel.
            settle_timeout: amount of blocks for the settle time (if None use defaults).

        Return:
            netting_channel: the (newly opened) netting channel object.
        """
        # Check, if peer is discoverable
        registry_address = TokenNetworkRegistryAddress(to_canonical_address(registry_address_hex))
        peer_address = to_canonical_address(peer_address_hex)
        token_address = TokenAddress(to_canonical_address(token_address_hex))

        self._api.channel_open(
            registry_address, token_address, peer_address, settle_timeout=settle_timeout
        )

        self._api.set_total_channel_deposit(
            registry_address, token_address, peer_address, total_deposit
        )

    def wait_for_contract(self, contract_address_hex: AddressHex, timeout: int = None) -> bool:
        """Wait until a contract is mined

        Args:
            contract_address_hex: hex encoded address of the contract
            timeout: time to wait for the contract to get mined

        Returns:
            True if the contract got mined, false otherwise
        """
        start_time = time.time()
        result = self._raiden.rpc_client.web3.eth.get_code(
            to_canonical_address(contract_address_hex)
        )

        current_time = time.time()
        while not result:
            if timeout and start_time + timeout > current_time:
                return False

            result = self._raiden.rpc_client.web3.eth.get_code(
                to_canonical_address(contract_address_hex)
            )
            gevent.sleep(0.5)

            current_time = time.time()

        return len(result) > 0
