from collections import Counter, defaultdict
from copy import deepcopy
from hashlib import sha256
from random import Random

import pytest
from hypothesis import assume, event
from hypothesis.stateful import (
    Bundle,
    RuleBasedStateMachine,
    consumes,
    initialize,
    invariant,
    multiple,
    rule,
)
from hypothesis.strategies import binary, builds, composite, integers, random_module, randoms

from raiden.constants import GENESIS_BLOCK_NUMBER, LOCKSROOT_OF_NO_LOCKS, UINT64_MAX
from raiden.settings import DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS, DEFAULT_WAIT_BEFORE_LOCK_REMOVAL
from raiden.tests.utils import factories
from raiden.transfer import channel, node
from raiden.transfer.channel import compute_locksroot
from raiden.transfer.events import EventPaymentSentFailed, SendProcessed
from raiden.transfer.mediated_transfer.events import (
    EventUnlockSuccess,
    SendBalanceProof,
    SendLockedTransfer,
    SendSecretReveal,
)
from raiden.transfer.mediated_transfer.state import LockedTransferSignedState
from raiden.transfer.mediated_transfer.state_change import (
    ActionInitInitiator,
    ActionInitMediator,
    ReceiveSecretRequest,
    ReceiveSecretReveal,
    TransferDescriptionWithSecretState,
)
from raiden.transfer.state import (
    ChainState,
    ChannelState,
    HashTimeLockState,
    NetworkState,
    TokenNetworkGraphState,
    TokenNetworkRegistryState,
    TokenNetworkState,
    make_empty_pending_locks_state,
)
from raiden.transfer.state_change import (
    Block,
    ContractReceiveChannelNew,
    ContractReceiveChannelSettled,
)
from raiden.utils import random_secret
from raiden.utils.typing import BlockNumber


@composite
def secret(draw):
    return draw(builds(random_secret))


@composite
def address(draw):
    return draw(binary(min_size=20, max_size=20))


@composite
def payment_id(draw):
    return draw(integers(min_value=1, max_value=UINT64_MAX))


def event_types_match(events, *expected_types):
    return Counter([type(event) for event in events]) == Counter(expected_types)


def transferred_amount(state):
    return 0 if not state.balance_proof else state.balance_proof.transferred_amount


# use of hypothesis.stateful.multiple() breaks the failed-example code
# generation at the moment, this function is a temporary workaround
def unwrap_multiple(multiple_results):
    values = multiple_results.values
    return values[0] if len(values) == 1 else values


partners = Bundle("partners")
# shared bundle of ChainStateStateMachine and all mixin classes


class ChainStateStateMachine(RuleBasedStateMachine):
    def __init__(self, address=None):
        self.address = address or factories.make_address()
        self.replay_path = False
        self.address_to_channel = dict()
        self.address_to_privkey = dict()
        self.initial_number_of_channels = 1

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
        self.address_to_channel[partner_address] = factories.create(
            factories.NettingChannelStateProperties(
                our_state=factories.NettingChannelEndStateProperties(
                    balance=1000, address=self.address
                ),
                partner_state=factories.NettingChannelEndStateProperties(
                    balance=1000, address=partner_address
                ),
                canonical_identifier=factories.make_canonical_identifier(
                    token_network_address=self.token_network_address
                ),
            )
        )

        return partner_address

    def new_channel_with_transaction(self):
        partner_address = self.new_channel()

        channel_new_state_change = ContractReceiveChannelNew(
            transaction_hash=factories.make_transaction_hash(),
            channel_state=self.address_to_channel[partner_address],
            block_number=self.block_number,
            block_hash=factories.make_block_hash(),
        )
        node.state_transition(self.chain_state, channel_new_state_change)
        self.chain_state.nodeaddresses_to_networkstates[partner_address] = NetworkState.REACHABLE

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

        self.token_network_address = factories.UNIT_TOKEN_NETWORK_ADDRESS
        self.token_id = factories.UNIT_TOKEN_ADDRESS
        self.token_network_state = TokenNetworkState(
            address=self.token_network_address,
            token_address=self.token_id,
            network_graph=TokenNetworkGraphState(self.token_network_address),
        )

        self.token_network_registry_address = factories.make_token_network_registry_address()
        self.token_network_registry_state = TokenNetworkRegistryState(
            self.token_network_registry_address, [self.token_network_state]
        )

        self.chain_state.identifiers_to_tokennetworkregistries[
            self.token_network_registry_address
        ] = self.token_network_registry_state

        self.chain_state.tokennetworkaddresses_to_tokennetworkregistryaddresses[
            self.token_network_address
        ] = self.token_network_registry_address
        channels = [
            self.new_channel_with_transaction() for _ in range(self.initial_number_of_channels)
        ]
        return multiple(*channels)

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
            partner_unclaimed = channel.get_amount_unclaimed_onchain(netting_channel.partner_state)
            assert our_transferred >= self.our_previous_transferred[address]
            assert partner_transferred >= self.partner_previous_transferred[address]
            assert (
                our_unclaimed + our_transferred
                >= self.our_previous_transferred[address] + self.our_previous_unclaimed[address]
            )
            assert (
                partner_unclaimed + partner_transferred
                >= self.partner_previous_transferred[address]
                + self.partner_previous_unclaimed[address]
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
            assert -our_deposit <= netted_transferred <= partner_deposit

    def channel_opened(self, partner_address):
        needed_channel = self.address_to_channel[partner_address]
        return channel.get_status(needed_channel) == ChannelState.STATE_OPENED


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
        return ActionInitInitiator(transfer, [factories.make_route_from_channel(channel)])

    def _receive_secret_request(self, transfer: TransferDescriptionWithSecretState):
        secrethash = sha256(transfer.secret).digest()
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
            token_network_registry_address=self.token_network_registry_address,
            payment_identifier=payment_id,
            amount=amount,
            token_network_address=self.token_network_address,
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
            assume(self.channel_opened(action.transfer.target))

    def _is_removed(self, action):
        expiry = self.expected_expiry[action.transfer.secrethash]
        return self.block_number >= expiry + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

    init_initiators = Bundle("init_initiators")

    @rule(
        target=init_initiators,
        partner=partners,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
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
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        excess_amount=integers(min_value=1),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def exceeded_capacity_init_initiator(self, partner, payment_id, excess_amount, secret):
        amount = self._available_amount(partner) + excess_amount
        transfer = self._new_transfer_description(partner, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert event_types_match(result.events, EventPaymentSentFailed)
        self.event("ActionInitInitiator failed: Amount exceeded")

    @rule(
        previous_action=init_initiators,
        partner=partners,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1),
    )
    def used_secret_init_initiator(self, previous_action, partner, payment_id, amount):
        assume(not self._is_removed(previous_action))
        secret = previous_action.transfer.secret
        transfer = self._new_transfer_description(partner, payment_id, amount, secret)
        action = self._action_init_initiator(transfer)
        result = node.state_transition(self.chain_state, action)
        assert not result.events
        self.event("ActionInitInitiator failed: Secret already in use.")

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
            self.event("Valid SecretRequest dropped due to previous invalid one.")
        elif self._is_removed(previous_action):
            assert not result.events
            self.event("Ohterwise valid SecretRequest dropped due to expired lock.")
        else:
            assert event_types_match(result.events, SendSecretReveal)
            self.event("Valid SecretRequest accepted.")
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
        previous_action=init_initiators, secret=secret()  # pylint: disable=no-value-for-parameter
    )
    def secret_request_with_wrong_secrethash(self, previous_action, secret):
        assume(sha256(secret).digest() != sha256(previous_action.transfer.secret).digest())
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


class BalanceProofData:
    def __init__(self, canonical_identifier):
        self._canonical_identifier = canonical_identifier
        self._pending_locks = make_empty_pending_locks_state()
        self.properties = None

    def update(self, amount, lock):
        self._pending_locks = channel.compute_locks_with(self._pending_locks, lock)
        if self.properties:
            self.properties = factories.replace(
                self.properties,
                locked_amount=self.properties.locked_amount + amount,
                locksroot=compute_locksroot(self._pending_locks),
                nonce=self.properties.nonce + 1,
            )
        else:
            self.properties = factories.BalanceProofProperties(
                transferred_amount=0,
                locked_amount=amount,
                nonce=1,
                locksroot=compute_locksroot(self._pending_locks),
                canonical_identifier=self._canonical_identifier,
            )


class MediatorMixin:
    def __init__(self):
        super().__init__()
        self.partner_to_balance_proof_data = dict()
        self.secrethash_to_secret = dict()
        self.waiting_for_unlock = dict()
        self.initial_number_of_channels = 2

    def _get_balance_proof_data(self, partner):
        if partner not in self.partner_to_balance_proof_data:
            partner_channel = self.address_to_channel[partner]
            self.partner_to_balance_proof_data[partner] = BalanceProofData(
                canonical_identifier=partner_channel.canonical_identifier
            )
        return self.partner_to_balance_proof_data[partner]

    def _update_balance_proof_data(self, partner, amount, expiration, secret):
        expected = self._get_balance_proof_data(partner)
        lock = HashTimeLockState(
            amount=amount, expiration=expiration, secrethash=sha256(secret).digest()
        )
        expected.update(amount, lock)
        return expected

    init_mediators = Bundle("init_mediators")
    secret_requests = Bundle("secret_requests")
    unlocks = Bundle("unlocks")

    def _new_mediator_transfer(
        self, initiator_address, target_address, payment_id, amount, secret
    ) -> LockedTransferSignedState:
        initiator_pkey = self.address_to_privkey[initiator_address]
        balance_proof_data = self._update_balance_proof_data(
            initiator_address, amount, self.block_number + 10, secret
        )
        self.secrethash_to_secret[sha256(secret).digest()] = secret

        return factories.create(
            factories.LockedTransferSignedStateProperties(
                **balance_proof_data.properties.__dict__,
                amount=amount,
                expiration=self.block_number + 10,
                payment_identifier=payment_id,
                secret=secret,
                initiator=initiator_address,
                target=target_address,
                token=self.token_id,
                sender=initiator_address,
                recipient=self.address,
                pkey=initiator_pkey,
                message_identifier=1,
            )
        )

    def _action_init_mediator(self, transfer: LockedTransferSignedState) -> ActionInitMediator:
        initiator_channel = self.address_to_channel[transfer.initiator]
        target_channel = self.address_to_channel[transfer.target]

        return ActionInitMediator(
            route_states=[factories.make_route_from_channel(target_channel)],
            from_hop=factories.make_hop_to_channel(initiator_channel),
            from_transfer=transfer,
            balance_proof=transfer.balance_proof,
            sender=transfer.balance_proof.sender,
        )

    @rule(
        target=init_mediators,
        initiator_address=partners,
        target_address=partners,
        payment_id=payment_id(),  # pylint: disable=no-value-for-parameter
        amount=integers(min_value=1, max_value=100),
        secret=secret(),  # pylint: disable=no-value-for-parameter
    )
    def valid_init_mediator(self, initiator_address, target_address, payment_id, amount, secret):
        assume(initiator_address != target_address)

        transfer = self._new_mediator_transfer(
            initiator_address, target_address, payment_id, amount, secret
        )
        action = self._action_init_mediator(transfer)
        result = node.state_transition(self.chain_state, action)

        assert event_types_match(result.events, SendProcessed, SendLockedTransfer)

        return action

    @rule(target=secret_requests, previous_action=consumes(init_mediators))
    def valid_receive_secret_reveal(self, previous_action):
        secret = self.secrethash_to_secret[previous_action.from_transfer.lock.secrethash]
        sender = previous_action.from_transfer.target
        recipient = previous_action.from_transfer.initiator

        action = ReceiveSecretReveal(secret=secret, sender=sender)
        result = node.state_transition(self.chain_state, action)

        expiration = previous_action.from_transfer.lock.expiration
        in_time = self.block_number < expiration - DEFAULT_NUMBER_OF_BLOCK_CONFIRMATIONS
        still_waiting = self.block_number < expiration + DEFAULT_WAIT_BEFORE_LOCK_REMOVAL

        if in_time and self.channel_opened(sender) and self.channel_opened(recipient):
            assert event_types_match(
                result.events, SendSecretReveal, SendBalanceProof, EventUnlockSuccess
            )
            self.event("Unlock successful.")
            self.waiting_for_unlock[secret] = recipient
        elif still_waiting and self.channel_opened(recipient):
            assert event_types_match(result.events, SendSecretReveal)
            self.event("Unlock failed, secret revealed too late.")
        else:
            assert not result.events
            self.event("ReceiveSecretRevealed after removal of lock - dropped.")
        return action

    @rule(previous_action=secret_requests)
    def replay_receive_secret_reveal(self, previous_action):
        result = node.state_transition(self.chain_state, previous_action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(previous_action=secret_requests, invalid_sender=address())
    # pylint: enable=no-value-for-parameter
    def replay_receive_secret_reveal_scrambled_sender(self, previous_action, invalid_sender):
        action = ReceiveSecretReveal(previous_action.secret, invalid_sender)
        result = node.state_transition(self.chain_state, action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(previous_action=init_mediators, secret=secret())
    # pylint: enable=no-value-for-parameter
    def wrong_secret_receive_secret_reveal(self, previous_action, secret):
        sender = previous_action.from_transfer.target
        action = ReceiveSecretReveal(secret, sender)
        result = node.state_transition(self.chain_state, action)
        assert not result.events

    # pylint: disable=no-value-for-parameter
    @rule(
        target=secret_requests, previous_action=consumes(init_mediators), invalid_sender=address()
    )
    # pylint: enable=no-value-for-parameter
    def wrong_address_receive_secret_reveal(self, previous_action, invalid_sender):
        secret = self.secrethash_to_secret[previous_action.from_transfer.lock.secrethash]
        invalid_action = ReceiveSecretReveal(secret, invalid_sender)
        result = node.state_transition(self.chain_state, invalid_action)
        assert not result.events

        valid_sender = previous_action.from_transfer.target
        valid_action = ReceiveSecretReveal(secret, valid_sender)
        return valid_action


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
            canonical_identifier=factories.make_canonical_identifier(
                chain_identifier=channel.chain_id,
                token_network_address=channel.token_network_address,
                channel_identifier=channel.identifier,
            ),
            block_number=self.block_number + 1,
            block_hash=factories.make_block_hash(),
            our_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
            partner_onchain_locksroot=LOCKSROOT_OF_NO_LOCKS,
        )

        node.state_transition(self.chain_state, channel_settled_state_change)


class InitiatorStateMachine(InitiatorMixin, ChainStateStateMachine):
    pass


class MediatorStateMachine(MediatorMixin, ChainStateStateMachine):
    pass


class OnChainStateMachine(OnChainMixin, ChainStateStateMachine):
    pass


class MultiChannelInitiatorStateMachine(InitiatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


class MultiChannelMediatorStateMachine(MediatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


class FullStateMachine(InitiatorMixin, MediatorMixin, OnChainMixin, ChainStateStateMachine):
    pass


TestInitiator = InitiatorStateMachine.TestCase
TestMediator = MediatorStateMachine.TestCase
TestOnChain = OnChainStateMachine.TestCase
TestMultiChannelInitiator = MultiChannelInitiatorStateMachine.TestCase
TestMultiChannelMediator = MultiChannelMediatorStateMachine.TestCase
TestFullStateMachine = FullStateMachine.TestCase


def test_regression_malicious_secret_request_handled_properly():
    state = InitiatorStateMachine()
    state.replay_path = True

    v1 = unwrap_multiple(state.initialize(block_number=1, random=Random(), random_seed=None))
    v2 = state.valid_init_initiator(partner=v1, amount=1, payment_id=1, secret=b"\x00" * 32)
    state.wrong_amount_secret_request(amount=0, previous_action=v2)
    state.replay_init_initator(previous_action=v2)

    state.teardown()


@pytest.mark.skip
def test_try_secret_request_after_settle_channel():
    state = MultiChannelInitiatorStateMachine()
    state.replay_path = True
    state.failing_path_2 = True

    v1 = state.initialize(block_number=1, random=Random(), random_seed=None)
    v2 = state.valid_init_initiator(amount=1, partner=v1, payment_id=1, secret=b"\x91" * 32)
    state.settle_channel(partner=v1)
    state.valid_secret_request(previous_action=v2)

    state.teardown()
