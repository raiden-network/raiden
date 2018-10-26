from hypothesis import assume
from hypothesis.stateful import Bundle, RuleBasedStateMachine, initialize, rule
from hypothesis.strategies import binary, composite, integers, random_module, randoms

from raiden.tests.utils import factories
from raiden.transfer import channel, node
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendSecretReveal
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveSecretRequest,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState
from raiden.transfer.state_change import ContractReceiveChannelNew
from raiden.utils import sha3


@composite
def secret(draw):
    return draw(binary(min_size=32, max_size=32))


def event_types_match(events, types):
    return (
        len(events) == len(types) and
        all(isinstance(event, type) for (event, type) in zip(events, types))
    )


class InitiatorState(RuleBasedStateMachine):

    @initialize(block_number=integers(min_value=1), random=randoms(), random_seed=random_module())
    def initialize(self, block_number, random, random_seed):
        self.random_seed = random_seed

        self.block_number = block_number
        self.random = random
        self.private_key, self.address = factories.make_privkey_address()

        self.chain_state = ChainState(
            self.random,
            self.block_number,
            self.address,
            factories.UNIT_CHAIN_ID,
        )

        self.token_network_id = factories.make_address()
        self.token_id = factories.make_address()
        self.token_network_state = TokenNetworkState(self.token_network_id, self.token_id)

        self.payment_network_id = factories.make_payment_network_identifier()
        self.payment_network_state = PaymentNetworkState(
            self.payment_network_id,
            [self.token_network_state],
        )

        self.chain_state.identifiers_to_paymentnetworks[
            self.payment_network_id
        ] = self.payment_network_state

        self.channel = factories.make_channel(
            our_balance=1000,
            token_network_identifier=self.token_network_id,
        )

        channel_new_state_change = ContractReceiveChannelNew(
            factories.make_transaction_hash(),
            self.token_network_id,
            self.channel,
            self.block_number,
        )

        node.state_transition(self.chain_state, channel_new_state_change)

    new_transfers = Bundle('new_transfers')
    pending_transfers = Bundle('pending_transfers')

    @rule(
        target=new_transfers,
        payment_id=integers(min_value=1),
        amount=integers(min_value=1, max_value=100),
        secret=secret(),
    )
    def populate_transfer_descriptions(self, payment_id, amount, secret):
        return TransferDescriptionWithSecretState(
            self.payment_network_id,
            payment_id,
            amount,
            self.token_network_id,
            self.address,
            self.channel.partner_state.address,  # target
            secret,
        )

    def _secret_in_use(self, secret):
        return sha3(secret) in self.chain_state.payment_mapping.secrethashes_to_task

    def _available_amount(self):
        deposit = self.channel.our_total_deposit
        locked = channel.get_amount_locked(self.channel.our_state)
        return deposit - locked

    def _action_init_initiator(self, transfer: TransferDescriptionWithSecretState):
        return ActionInitInitiator(
            transfer,
            [factories.route_from_channel(self.channel)],
        )

    def _receive_secret_request(self, transfer: TransferDescriptionWithSecretState):
        secrethash = sha3(transfer.secret)
        return ReceiveSecretRequest(
            transfer.payment_identifier,
            transfer.amount,
            self.block_number + 10,  # todo
            secrethash,
            transfer.target,
        )

    @rule(target=pending_transfers, transfer=new_transfers)
    def valid_init_transfer(self, transfer):
        assume(not self._secret_in_use(transfer.secret))
        assume(transfer.amount <= self._available_amount())
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert event_types_match(result.events, [SendLockedTransfer])
        return transfer

    @rule(transfer=pending_transfers)
    def valid_secret_request(self, transfer):
        action = self._receive_secret_request(transfer)
        result = node.state_transition(self.chain_state, action)
        assert event_types_match(result.events, [SendSecretReveal])


TestInitiator = InitiatorState.TestCase
