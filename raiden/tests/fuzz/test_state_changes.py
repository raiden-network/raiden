from collections import Counter, defaultdict
from copy import deepcopy
from random import Random

import pytest
from hypothesis import assume, event
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    consumes,
    initialize,
    invariant,
    rule,
)
from hypothesis.strategies import builds, composite, integers, random_module, randoms

from raiden.constants import GENESIS_BLOCK_NUMBER
from raiden.settings import DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
from raiden.tests.utils import factories
from raiden.transfer import channel, node
from raiden.transfer.events import EventPaymentSentFailed
from raiden.transfer.mediated_transfer.events import SendLockedTransfer, SendSecretReveal
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ReceiveSecretRequest,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import ChainState, PaymentNetworkState, TokenNetworkState
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
)
from raiden.utils import random_secret, sha3
from raiden.utils.typing import BlockNumber


@composite
def secret(draw):
    return draw(builds(random_secret))


def event_types_match(events, *expected_types):
    return Counter([type(event) for event in events]) == Counter(expected_types)


def transferred_amount(state):
    return 0 if not state.balance_proof else state.balance_proof.transferred_amount


partners = Bundle('partners')
# shared bundle of ChainStateStateMachine and all mixin classes


class ChainStateStateMachine(RuleBasedStateMachine):

    def __init__(self, address=None):
        self.address = address or factories.make_address()
        self.replay_path = False
        self.address_to_channel = dict()
        self.address_to_privkey = dict()

        self.our_previous_deposit = defaultdict(int)
        self.partner_previous_deposit = defaultdict(int)
        self.our_previous_transferred = defaultdict(int)
        self.partner_previous_transferred = defaultdict(int)
        self.our_previous_unclaimed = defaultdict(int)
        self.partner_previous_unclaimed = defaultdict(int)

        self.expected_expiry = dict()

        super().__init__()

    def new_channel(self):
        """Create a new partner address with private key and channel. The
        private key and channels are listed in the instance's dictionaries,
        the address is returned and should be added to the partners Bundle.
        """

        partner_privkey, partner_address = factories.make_privkey_address()

        self.address_to_privkey[partner_address] = partner_privkey
        self.address_to_channel[partner_address] = factories.make_channel(
            our_balance=1000,
            partner_balance=1000,
            token_network_identifier=self.token_network_id,
            our_address=self.address,
            partner_address=partner_address,
        )

        return partner_address

    def new_channel_with_transaction(self):
        partner_address = self.new_channel()

        channel_new_state_change = ContractReceiveChannelNew(
            transaction_hash=factories.make_transaction_hash(),
            token_network_identifier=self.token_network_id,
            channel_state=self.address_to_channel[partner_address],
            block_number=self.block_number,
            block_hash=factories.make_block_hash(),
        )
        node.state_transition(self.chain_state, channel_new_state_change)

        return partner_address

    @initialize(
        target=partners,
        block_number=integers(min_value=GENESIS_BLOCK_NUMBER + 1),
        random=randoms(),
        random_seed=random_module(),
    )
    def initialize(self, block_number, random, random_seed):
        self.random_seed = random_seed

        self.block_number = block_number
        self.block_hash = factories.make_block_hash()
        self.random = random
        self.private_key, self.address = factories.make_privkey_address()

        self.chain_state = ChainState(
            pseudo_random_generator=self.random,
            block_number=self.block_number,
            block_hash=self.block_hash,
            our_address=self.address,
            chain_id=factories.UNIT_CHAIN_ID,
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

        return self.new_channel_with_transaction()

    def event(self, description):
        """ Wrapper for hypothesis' event function.

        hypothesis.event raises an exception when invoked outside of hypothesis
        context, so skip it when we are replaying a failed path.
        """
        if not self.replay_path:
            event(description)

    @invariant()
    def monotonicity(self):
        """ Check monotonicity properties as given in Raiden specification """

        for address, netting_channel in self.address_to_channel.items():

            # constraint (1TN)
            assert netting_channel.our_total_deposit >= self.our_previous_deposit[address]
            assert netting_channel.partner_total_deposit >= self.partner_previous_deposit[address]
            self.our_previous_deposit[address] = netting_channel.our_total_deposit
            self.partner_previous_deposit[address] = netting_channel.partner_total_deposit

            # TODO add constraint (2TN) when withdrawal is implemented
            # constraint (3R) and (4R)
            our_transferred = transferred_amount(netting_channel.our_state)
            partner_transferred = transferred_amount(netting_channel.partner_state)
            our_unclaimed = channel.get_amount_unclaimed_onchain(netting_channel.our_state)
            partner_unclaimed = channel.get_amount_unclaimed_onchain(
                netting_channel.partner_state,
            )
            assert our_transferred >= self.our_previous_transferred[address]
            assert partner_transferred >= self.partner_previous_transferred[address]
            assert (
                our_unclaimed + our_transferred >=
                self.our_previous_transferred[address] + self.our_previous_unclaimed[address]
            )
            assert (
                partner_unclaimed + partner_transferred >=
                self.our_previous_transferred[address] + self.our_previous_unclaimed[address]
            )
            self.our_previous_transferred[address] = our_transferred
            self.partner_previous_transferred[address] = partner_transferred
            self.our_previous_unclaimed[address] = our_unclaimed
            self.partner_previous_unclaimed[address] = partner_unclaimed

    @invariant()
    def channel_state_invariants(self):
        """ Check the invariants for the channel state given in the Raiden specification """

        for netting_channel in self.address_to_channel.values():
            our_state = netting_channel.our_state
            partner_state = netting_channel.partner_state

            our_transferred_amount = 0
            if our_state.balance_proof:
                our_transferred_amount = our_state.balance_proof.transferred_amount
                assert our_transferred_amount >= 0

            partner_transferred_amount = 0
            if partner_state.balance_proof:
                partner_transferred_amount = partner_state.balance_proof.transferred_amount
                assert partner_transferred_amount >= 0

            assert channel.get_distributable(our_state, partner_state) >= 0
            assert channel.get_distributable(partner_state, our_state) >= 0

            our_deposit = netting_channel.our_total_deposit
            partner_deposit = netting_channel.partner_total_deposit
            total_deposit = our_deposit + partner_deposit

            our_amount_locked = channel.get_amount_locked(our_state)
            our_balance = channel.get_balance(our_state, partner_state)
            partner_amount_locked = channel.get_amount_locked(partner_state)
            partner_balance = channel.get_balance(partner_state, our_state)

            # invariant (5.1R), add withdrawn amounts when implemented
            assert 0 <= our_amount_locked <= our_balance
            assert 0 <= partner_amount_locked <= partner_balance
            assert our_amount_locked <= total_deposit
            assert partner_amount_locked <= total_deposit

            our_transferred = partner_transferred_amount - our_transferred_amount
            netted_transferred = our_transferred + partner_amount_locked - our_amount_locked

            # invariant (6R), add withdrawn amounts when implemented
            assert 0 <= our_deposit + our_transferred - our_amount_locked <= total_deposit
            assert 0 <= partner_deposit - our_transferred - partner_amount_locked <= total_deposit

            # invariant (7R), add withdrawn amounts when implemented
            assert - our_deposit <= netted_transferred <= partner_deposit


class InitiatorMixin:

    def __init__(self):
        super().__init__()
        self.used_secrets = set()
        self.processed_secret_requests = set()
        self.initiated = set()
        self.failing_path_2 = False

    def _action_init_initiator(self, transfer: TransferDescriptionWithSecretState):
        channel = self.address_to_channel[transfer.target]
        if transfer.secrethash not in self.expected_expiry:
            self.expected_expiry[transfer.secrethash] = self.block_number + 10
        return ActionInitInitiator(
            transfer,
            [factories.route_from_channel(channel)],
        )

    def _receive_secret_request(self, transfer: TransferDescriptionWithSecretState):
        secrethash = sha3(transfer.secret)
        return ReceiveSecretRequest(
            payment_identifier=transfer.payment_identifier,
            amount=transfer.amount,
            expiration=self.expected_expiry[transfer.secrethash],
            secrethash=secrethash,
            sender=transfer.target,
        )

    def _new_transfer_description(self, target, payment_id, amount, secret):
        self.used_secrets.add(secret)

        return TransferDescriptionWithSecretState(
            payment_network_identifier=self.payment_network_id,
            payment_identifier=payment_id,
            amount=amount,
            token_network_identifier=self.token_network_id,
            initiator=self.address,
            target=target,
            secret=secret,
        )

    def _invalid_authentic_secret_request(self, previous, action):
        result = node.state_transition(self.chain_state, action)
        if action.secrethash in self.processed_secret_requests or self._is_removed(previous):
            assert not result.events
        else:
            self.processed_secret_requests.add(action.secrethash)

    def _unauthentic_secret_request(self, action):
        result = node.state_transition(self.chain_state, action)
        assert not result.events

    def _available_amount(self, partner_address):
        netting_channel = self.address_to_channel[partner_address]
        return channel.get_distributable(netting_channel.our_state, netting_channel.partner_state)

    def _assume_channel_opened(self, action):
        if not self.failing_path_2:
            needed_channel = self.address_to_channel[action.transfer.target]
            assume(channel.get_status(needed_channel) == channel.CHANNEL_STATE_OPENED)

    def _is_removed(self, action):
        expiry = self.expected_expiry[action.transfer.secrethash]
        return self.block_number >= expiry + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

    init_initiators = Bundle('init_initiators')

    @rule(
        target=init_initiators,
        partner=partners,
        payment_id=integers(min_value=1),
        amount=integers(min_value=1, max_value=100),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def valid_init_initiator(self, partner, payment_id, amount, secret):
        assume(amount <= self._available_amount(partner))
        assume(secret not in self.used_secrets)

        transfer = self._new_transfer_description(partner, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)

        assert event_types_match(result.events, SendLockedTransfer)

        self.initiated.add(transfer.secret)
        self.expected_expiry[transfer.secrethash] = self.block_number + 10

        return action

    @rule(
        partner=partners,
        payment_id=integers(min_value=1),
        excess_amount=integers(min_value=1),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def exceeded_capacity_init_initiator(self, partner, payment_id, excess_amount, secret):
        amount = self._available_amount(partner) + excess_amount
        transfer = self._new_transfer_description(partner, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert event_types_match(result.events, EventPaymentSentFailed)
        self.event('ActionInitInitiator failed: Amount exceeded')

    @rule(
        previous_action=init_initiators,
        partner=partners,
        payment_id=integers(min_value=1),
        amount=integers(min_value=1),
    )
    def used_secret_init_initiator(self, previous_action, partner, payment_id, amount):
        assume(not self._is_removed(previous_action))
        secret = previous_action.transfer.secret
        transfer = self._new_transfer_description(partner, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert not result.events
        self.event('ActionInitInitiator failed: Secret already in use.')

    @rule(previous_action=init_initiators)
    def replay_init_initator(self, previous_action):
        assume(not self._is_removed(previous_action))
        result = node.state_transition(self.chain_state, previous_action)
        assert not result.events

    @rule(previous_action=init_initiators)
    def valid_secret_request(self, previous_action):
        action = self._receive_secret_request(previous_action.transfer)
        self._assume_channel_opened(previous_action)
        result = node.state_transition(self.chain_state, action)
        if action.secrethash in self.processed_secret_requests:
            assert not result.events
            self.event('Valid SecretRequest dropped due to previous invalid one.')
        elif self._is_removed(previous_action):
            assert not result.events
            self.event('Ohterwise valid SecretRequest dropped due to expired lock.')
        else:
            assert event_types_match(result.events, SendSecretReveal)
            self.event('Valid SecretRequest accepted.')
            self.processed_secret_requests.add(action.secrethash)

    @rule(previous_action=init_initiators, amount=integers())
    def wrong_amount_secret_request(self, previous_action, amount):
        assume(amount != previous_action.transfer.amount)
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.amount = amount
        action = self._receive_secret_request(transfer)
        self._invalid_authentic_secret_request(previous_action, action)

    @rule(
        previous_action=init_initiators,
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def secret_request_with_wrong_secrethash(self, previous_action, secret):
        assume(sha3(secret) != sha3(previous_action.transfer.secret))
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.secret = secret
        action = self._receive_secret_request(transfer)
        return self._unauthentic_secret_request(action)

    @rule(previous_action=init_initiators, payment_identifier=integers())
    def secret_request_with_wrong_payment_id(self, previous_action, payment_identifier):
        assume(payment_identifier != previous_action.transfer.payment_identifier)
        self._assume_channel_opened(previous_action)
        transfer = deepcopy(previous_action.transfer)
        transfer.payment_identifier = payment_identifier
        action = self._receive_secret_request(transfer)
        self._unauthentic_secret_request(action)


class OnChainMixin:

    block_number: BlockNumber

    @rule(number=integers(min_value=1, max_value=50))
    def new_blocks(self, number):
        events = list()

        for _ in range(number):
            block_state_change = Block(
                block_number=self.block_number + 1,
                gas_limit=1,
                block_hash=factories.make_keccak_hash(),
            )
            result = node.state_transition(self.chain_state, block_state_change)
            events.extend(result.events)

            self.block_number += 1

    @rule(target=partners)
    def open_channel(self):
        return self.new_channel_with_transaction()

    @rule(partner=consumes(partners))
    def settle_channel(self, partner):
        channel = self.address_to_channel[partner]

        channel_settled_state_change = ContractReceiveChannelSettled(
            transaction_hash=factories.make_transaction_hash(),
            token_network_identifier=channel.token_network_identifier,
            channel_identifier=channel.identifier,
            block_number=self.block_number + 1,
            block_hash=factories.make_block_hash(),
        )

        node.state_transition(self.chain_state, channel_settled_state_change)


class InitiatorStateMachine(InitiatorMixin, ChainStateStateMachine):
    pass


class OnChainStateMachine(OnChainMixin, ChainStateStateMachine):
    pass


class MultiChannelInitiatorStateMachine(InitiatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


TestInitiator = InitiatorStateMachine.TestCase
TestOnChain = OnChainStateMachine.TestCase
TestMultiChannelInitiator = MultiChannelInitiatorStateMachine.TestCase


def test_regression_malicious_secret_request_handled_properly():
    state = InitiatorStateMachine()
    state.replay_path = True

    v1 = state.initialize(block_number=1, random=Random(), random_seed=None)
    v2 = state.valid_init_initiator(
        partner=v1,
        amount=1,
        payment_id=1,
        secret=b'\x00' * 32,
    )
    state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.replay_init_initator(previous_action=v2)

    state.teardown()


@pytest.mark.skip
def test_try_secret_request_after_settle_channel():
    state = MultiChannelInitiatorStateMachine()
    state.replay_path = True
    state.failing_path_2 = True

    v1 = state.initialize(block_number=1, random=Random(), random_seed=None)
    v2 = state.valid_init_initiator(amount=1, partner=v1, payment_id=1, secret=b'\x91' * 32)
    state.settle_channel(partner=v1)
    state.valid_secret_request(previous_action=v2)

    state.teardown()
