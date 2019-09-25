import json
import random
from collections import defaultdict
from unittest.mock import Mock, PropertyMock

from raiden.constants import RoutingMode
from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.identifiers import CanonicalIdentifier
from raiden.transfer.state_change import ActionInitChain
from raiden.utils import privatekey_to_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    Address,
    BlockSpecification,
    ChannelID,
    Dict,
    Optional,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.utils.type_aliases import ChainID


class MockJSONRPCClient:
    def __init__(self, address: Address):
        # To be manually set by each test
        self.balances_mapping: Dict[Address, int] = {}
        self.chain_id = ChainID(17)
        self.address = address

    @staticmethod
    def can_query_state_for_block(block_identifier):  # pylint: disable=unused-argument
        # To be changed by each test
        return True

    def gas_price(self):  # pylint: disable=unused-argument, no-self-use
        # 1 gwei
        return 1000000000

    def balance(self, address):
        return self.balances_mapping[address]


class MockTokenNetworkProxy:
    def __init__(self, client: MockJSONRPCClient):
        self.client = client

    @staticmethod
    def detail_participants(  # pylint: disable=unused-argument
        participant1, participant2, block_identifier, channel_identifier
    ):
        # To be changed by each test
        return None


class MockPaymentChannel:
    def __init__(self, token_network, channel_id):  # pylint: disable=unused-argument
        self.token_network = token_network


class MockProxyManager:
    def __init__(self, node_address: Address):
        # let's make a single mock token network for testing
        self.client = MockJSONRPCClient(node_address)
        self.token_network = MockTokenNetworkProxy(client=self.client)

    def payment_channel(self, canonical_identifier: CanonicalIdentifier):
        return MockPaymentChannel(self.token_network, canonical_identifier.channel_identifier)

    def token_network_registry(  # pylint: disable=unused-argument, no-self-use
        self, address: Address
    ):
        return Mock(address=address)

    def secret_registry(self, address: Address):  # pylint: disable=unused-argument, no-self-use
        return object()

    def user_deposit(self, address: Address):  # pylint: disable=unused-argument, no-self-use
        return object()

    def service_registry(self, address: Address):  # pylint: disable=unused-argument, no-self-use
        return object()


class MockChannelState:
    def __init__(self):
        self.settle_transaction = None
        self.close_transaction = None
        self.our_state = Mock()
        self.partner_state = Mock()


class MockTokenNetwork:
    def __init__(self):
        self.channelidentifiers_to_channels = {}
        self.partneraddresses_to_channelidentifiers = {}


class MockTokenNetworkRegistry:
    def __init__(self):
        self.tokennetworkaddresses_to_tokennetworks = {}


class MockChainState:
    def __init__(self):
        self.identifiers_to_tokennetworkregistries = {}


class MockRaidenService:
    def __init__(self, message_handler=None, state_transition=None, private_key=None, config=None):
        if private_key is None:
            self.privkey, self.address = factories.make_privkey_address()
        else:
            self.privkey = private_key
            self.address = privatekey_to_address(private_key)

        self.rpc_client = MockJSONRPCClient(self.address)
        self.proxy_manager = MockProxyManager(node_address=self.address)
        self.signer = LocalSigner(self.privkey)

        self.message_handler = message_handler
        self.routing_mode = RoutingMode.PRIVATE
        self.config = config

        self.user_deposit = Mock()
        self.default_registry = Mock()
        self.default_registry.address = factories.make_address()
        self.default_one_to_n_address = factories.make_address()
        self.default_msc_address = factories.make_address()

        self.targets_to_identifiers_to_statuses = defaultdict(dict)
        self.route_to_feedback_token = {}

        if state_transition is None:
            state_transition = node.state_transition

        serializer = JSONSerializer
        state_manager = StateManager(state_transition, None)
        storage = SerializedSQLiteStorage(":memory:", serializer)
        self.wal = WriteAheadLog(state_manager, storage)

        state_change = ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=0,
            block_hash=factories.make_block_hash(),
            our_address=self.rpc_client.address,
            chain_id=self.rpc_client.chain_id,
        )

        self.wal.log_and_dispatch([state_change])

    def on_message(self, message):
        if self.message_handler:
            self.message_handler.on_message(self, message)

    def handle_and_track_state_changes(self, state_changes):
        pass

    def handle_state_changes(self, state_changes):
        pass

    def sign(self, message):
        message.sign(self.signer)


def make_raiden_service_mock(
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    partner: Address,
):
    raiden_service = MockRaidenService(config={})
    chain_state = MockChainState()
    wal = Mock()
    wal.state_manager.current_state = chain_state
    raiden_service.wal = wal

    token_network = MockTokenNetwork()
    token_network.channelidentifiers_to_channels[channel_identifier] = MockChannelState()
    token_network.partneraddresses_to_channelidentifiers[partner] = [channel_identifier]

    token_network_registry = MockTokenNetworkRegistry()
    tokennetworkaddresses_to_tokennetworks = (
        token_network_registry.tokennetworkaddresses_to_tokennetworks
    )
    tokennetworkaddresses_to_tokennetworks[token_network_address] = token_network

    chain_state.identifiers_to_tokennetworkregistries = {
        token_network_registry_address: token_network_registry
    }

    return raiden_service


def mocked_failed_response(error: Exception, status_code: int = 200) -> Mock:
    m = Mock(json=Mock(side_effect=error), status_code=status_code)

    type(m).content = PropertyMock(side_effect=error)
    return m


def mocked_json_response(response_data: Optional[Dict] = None, status_code: int = 200) -> Mock:
    data = response_data or {}
    return Mock(json=Mock(return_value=data), content=json.dumps(data), status_code=status_code)


class MockEth:
    def getBlock(  # pylint: disable=unused-argument, no-self-use
        self, block_identifier: BlockSpecification
    ) -> Dict:
        return {
            "number": 42,
            "hash": "0x8cb5f5fb0d888c03ec4d13f69d4eb8d604678508a1fa7c1a8f0437d0065b9b67",
        }


class MockWeb3Version:
    def __init__(self, netid):
        self.network = netid


class MockWeb3:
    def __init__(self, netid):
        self.version = MockWeb3Version(netid)
        self.eth = MockEth()
