import random
from unittest.mock import Mock, patch

import requests

from raiden.storage.serialize import JSONSerializer
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
    PaymentNetworkID,
    TokenNetworkID,
)


class MockJSONRPCClient:
    def __init__(self):
        # To be manually set by each test
        self.balances_mapping = {}

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
    def __init__(self):
        self.client = MockJSONRPCClient()

    @staticmethod
    def detail_participants(  # pylint: disable=unused-argument
        participant1, participant2, block_identifier, channel_identifier
    ):
        # To be changed by each test
        return None


class MockPaymentChannel:
    def __init__(self, token_network, channel_id):  # pylint: disable=unused-argument
        self.token_network = token_network


class MockChain:
    def __init__(self, network_id: int, node_address: Address):
        self.network_id = network_id
        # let's make a single mock token network for testing
        self.token_network = MockTokenNetworkProxy()
        self.node_address = node_address
        self.client = MockJSONRPCClient()

    def payment_channel(self, canonical_identifier: CanonicalIdentifier):
        return MockPaymentChannel(self.token_network, canonical_identifier.channel_identifier)

    def token_network_registry(  # pylint: disable=unused-argument, no-self-use
        self, address: Address
    ):
        return object()

    def discovery(self, address: Address):  # pylint: disable=unused-argument, no-self-use
        return object()

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


class MockPaymentNetwork:
    def __init__(self):
        self.tokenidentifiers_to_tokennetworks = {}


class MockChainState:
    def __init__(self):
        self.identifiers_to_paymentnetworks = {}


class MockRaidenService:
    def __init__(self, message_handler=None, state_transition=None, private_key=None):
        if private_key is None:
            self.private_key, self.address = factories.make_privkey_address()
        else:
            self.private_key = private_key
            self.address = privatekey_to_address(private_key)

        self.chain = MockChain(network_id=17, node_address=self.address)
        self.signer = LocalSigner(self.private_key)

        self.message_handler = message_handler

        self.user_deposit = Mock()

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
            our_address=self.chain.node_address,
            chain_id=self.chain.network_id,
        )

        self.wal.log_and_dispatch(state_change)

    def on_message(self, message):
        if self.message_handler:
            self.message_handler.on_message(self, message)

    def handle_and_track_state_change(self, state_change):
        pass

    def handle_state_change(self, state_change):
        pass

    def sign(self, message):
        message.sign(self.signer)


def make_raiden_service_mock(
    payment_network_identifier: PaymentNetworkID,
    token_network_identifier: TokenNetworkID,
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

    payment_network = MockPaymentNetwork()
    tokenidentifiers_to_tokennetworks = payment_network.tokenidentifiers_to_tokennetworks
    tokenidentifiers_to_tokennetworks[token_network_identifier] = token_network

    chain_state.identifiers_to_paymentnetworks = {payment_network_identifier: payment_network}
    return raiden_service


def patched_get_for_succesful_pfs_info():
    json_data = {
        "price_info": 0,
        "network_info": {
            "chain_id": 1,
            "registry_address": "0xB9633dd9a9a71F22C933bF121d7a22008f66B908",
        },
        "message": "This is your favorite pathfinding service",
        "operator": "John Doe",
        "version": "0.0.1",
    }

    response = Mock()
    response.configure_mock(status_code=200)
    response.json = Mock(return_value=json_data)
    return patch.object(requests, "get", return_value=response)


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
