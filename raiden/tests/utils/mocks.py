import json
import random
from collections import defaultdict
from unittest.mock import Mock, PropertyMock

from raiden.constants import Environment, RoutingMode
from raiden.settings import RaidenConfig
from raiden.storage.serialization import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.tests.utils.factories import UNIT_CHAIN_ID
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.state import NettingChannelState
from raiden.transfer.state_change import ActionInitChain
from raiden.utils.keys import privatekey_to_address
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    Address,
    BlockIdentifier,
    BlockNumber,
    ChannelID,
    Dict,
    Optional,
    TokenAmount,
    TokenNetworkAddress,
    TokenNetworkRegistryAddress,
)
from raiden_contracts.utils.type_aliases import ChainID


class MockJSONRPCClient:
    def __init__(self, address: Address):
        # To be manually set by each test
        self.balances_mapping: Dict[Address, TokenAmount] = {}
        self.chain_id = ChainID(UNIT_CHAIN_ID)
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
    def __init__(self, node_address: Address, mocked_addresses: Dict[str, Address] = None):
        # let's make a single mock token network for testing
        self.client = MockJSONRPCClient(node_address)
        self.token_network = MockTokenNetworkProxy(client=self.client)
        self.mocked_addresses = mocked_addresses or dict()

    def payment_channel(
        self, channel_state: NettingChannelState, block_identifier: BlockIdentifier
    ):  # pylint: disable=unused-argument
        return MockPaymentChannel(
            self.token_network, channel_state.canonical_identifier.channel_identifier
        )

    def token_network_registry(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=no-self-use,unused-argument
        registry = Mock(address=address)
        registry.get_secret_registry_address.return_value = self.mocked_addresses.get(
            "SecretRegistry", factories.make_address()
        )
        return registry

    def secret_registry(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=no-self-use, unused-argument
        return Mock(address=address)

    def user_deposit(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=unused-argument, no-self-use
        user_deposit = Mock()
        user_deposit.monitoring_service_address.return_value = self.mocked_addresses.get(
            "MonitoringService", bytes(20)
        )
        user_deposit.token_address.return_value = self.mocked_addresses.get("Token", bytes(20))
        user_deposit.one_to_n_address.return_value = self.mocked_addresses.get("OneToN", bytes(20))
        user_deposit.service_registry_address.return_value = self.mocked_addresses.get(
            "ServiceRegistry", bytes(20)
        )
        return user_deposit

    def service_registry(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=unused-argument, no-self-use
        service_registry = Mock()
        service_registry.address = self.mocked_addresses.get("ServiceRegistry", bytes(20))
        service_registry.token_address.return_value = self.mocked_addresses.get("Token", bytes(20))
        return service_registry

    def one_to_n(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=unused-argument, no-self-use
        one_to_n = Mock()
        one_to_n.address = self.mocked_addresses.get("MonitoringService", bytes(20))
        one_to_n.token_address.return_value = self.mocked_addresses.get("Token", bytes(20))
        return one_to_n

    def monitoring_service(
        self, address: Address, block_identifier: BlockIdentifier
    ):  # pylint: disable=unused-argument, no-self-use
        monitoring_service = Mock()
        monitoring_service.address = self.mocked_addresses.get("MonitoringService", bytes(20))
        monitoring_service.token_network_registry_address.return_value = self.mocked_addresses.get(
            "TokenNetworkRegistry", bytes(20)
        )
        monitoring_service.service_registry_address.return_value = self.mocked_addresses.get(
            "ServiceRegistry", bytes(20)
        )
        monitoring_service.token_address.return_value = self.mocked_addresses.get(
            "Token", bytes(20)
        )
        return monitoring_service


class MockChannelState:
    def __init__(self):
        self.settle_transaction = None
        self.close_transaction = None
        self.canonical_identifier = factories.make_canonical_identifier()
        self.our_state = Mock()
        self.partner_state = Mock()


class MockTokenNetwork:
    def __init__(self):
        self.channelidentifiers_to_channels: dict = {}
        self.partneraddresses_to_channelidentifiers: dict = {}


class MockTokenNetworkRegistry:
    def __init__(self):
        self.tokennetworkaddresses_to_tokennetworks: dict = {}


class MockChainState:
    def __init__(self):
        self.block_hash = factories.make_block_hash()
        self.identifiers_to_tokennetworkregistries: dict = {}


class MockRaidenService:
    def __init__(self, message_handler=None, state_transition=None, private_key=None):
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
        self.config = RaidenConfig(
            chain_id=self.rpc_client.chain_id, environment_type=Environment.DEVELOPMENT
        )

        self.default_user_deposit = Mock()
        self.default_registry = Mock()
        self.default_registry.address = factories.make_address()
        self.default_one_to_n_address = factories.make_address()
        self.default_msc_address = factories.make_address()

        self.targets_to_identifiers_to_statuses: Dict[Address, dict] = defaultdict(dict)
        self.route_to_feedback_token: dict = {}

        if state_transition is None:
            state_transition = node.state_transition

        serializer = JSONSerializer()
        state_manager = StateManager(state_transition, None)
        storage = SerializedSQLiteStorage(":memory:", serializer)
        self.wal = WriteAheadLog(state_manager, storage)

        state_change = ActionInitChain(
            pseudo_random_generator=random.Random(),
            block_number=BlockNumber(0),
            block_hash=factories.make_block_hash(),
            our_address=self.rpc_client.address,
            chain_id=self.rpc_client.chain_id,
        )

        self.wal.log_and_dispatch([state_change])
        self.transport = Mock()

    def on_messages(self, messages):
        if self.message_handler:
            self.message_handler.on_messages(self, messages)

    def handle_and_track_state_changes(self, state_changes):
        pass

    def handle_state_changes(self, state_changes):
        pass

    def sign(self, message):
        message.sign(self.signer)

    def stop(self):
        self.wal.storage.close()

    def __del__(self):
        self.stop()


def make_raiden_service_mock(
    token_network_registry_address: TokenNetworkRegistryAddress,
    token_network_address: TokenNetworkAddress,
    channel_identifier: ChannelID,
    partner: Address,
):
    raiden_service = MockRaidenService()
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
    def __init__(self, chain_id):
        self.chain_id = chain_id

    def getBlock(  # pylint: disable=unused-argument, no-self-use
        self, block_identifier: BlockIdentifier
    ) -> Dict:
        return {
            "number": 42,
            "hash": "0x8cb5f5fb0d888c03ec4d13f69d4eb8d604678508a1fa7c1a8f0437d0065b9b67",
        }

    @property
    def chainId(self):
        return self.chain_id


class MockWeb3:
    def __init__(self, chain_id):
        self.eth = MockEth(chain_id=chain_id)
