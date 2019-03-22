import random
from unittest.mock import Mock

from raiden.storage.serialize import JSONSerializer
from raiden.storage.sqlite import SerializedSQLiteStorage
from raiden.storage.wal import WriteAheadLog
from raiden.tests.utils import factories
from raiden.transfer import node
from raiden.transfer.architecture import StateManager
from raiden.transfer.state_change import ActionInitChain
from raiden.utils import CanonicalIdentifier
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import Address, ChannelID, PaymentNetworkID, TokenNetworkID


class MockJSONRPCClient:

    @staticmethod
    def can_query_state_for_block(block_identifier):  # pylint: disable=unused-argument
        # To be changed by each test
        return True


class MockTokenNetworkProxy:
    def __init__(self):
        self.client = MockJSONRPCClient()

    @staticmethod
    def detail_participants(  # pylint: disable=unused-argument
            participant1,
            participant2,
            block_identifier,
            channel_identifier,
    ):
        # To be changed by each test
        return None


class MockPaymentChannel:
    def __init__(self, token_network, channel_id):  # pylint: disable=unused-argument
        self.token_network = token_network


class MockChain:
    def __init__(self):
        self.network_id = 17
        # let's make a single mock token network for testing
        self.token_network = MockTokenNetworkProxy()

    def payment_channel(self, canonical_identifier: CanonicalIdentifier):
        return MockPaymentChannel(self.token_network, canonical_identifier.channel_identifier)


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
    def __init__(self, message_handler=None, state_transition=None):
        self.chain = MockChain()
        self.private_key, self.address = factories.make_privatekey_address()
        self.signer = LocalSigner(self.private_key)

        self.chain.node_address = self.address
        self.message_handler = message_handler

        self.user_deposit = Mock()

        if state_transition is None:
            state_transition = node.state_transition

        serializer = JSONSerializer
        state_manager = StateManager(state_transition, None)
        storage = SerializedSQLiteStorage(':memory:', serializer)
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

    chain_state.identifiers_to_paymentnetworks = {
        payment_network_identifier: payment_network,
    }
    return raiden_service
