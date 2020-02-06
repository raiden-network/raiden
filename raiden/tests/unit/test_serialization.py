import json
import os
import random
from dataclasses import dataclass
from datetime import datetime

import pytest
from eth_utils import to_canonical_address
from networkx import Graph

from raiden.exceptions import SerializationError
from raiden.messages.monitoring_service import RequestMonitoring, SignedBlindedBalanceProof
from raiden.messages.path_finding_service import PFSCapacityUpdate, PFSFeeUpdate
from raiden.messages.synchronization import Delivered, Processed
from raiden.messages.transfers import RevealSecret, SecretRequest
from raiden.messages.withdraw import WithdrawConfirmation, WithdrawExpired, WithdrawRequest
from raiden.storage.serialization import JSONSerializer
from raiden.storage.serialization.serializer import MessageSerializer
from raiden.tests.utils import factories
from raiden.transfer import state, state_change
from raiden.utils.signer import LocalSigner

# Required for test_message_identical. It would be better to have a set of
# messages that don't depend on randomness for that test. But right now, we
# don't have that.
random.seed(1)

message_factories = (
    factories.LockedTransferProperties(),
    factories.RefundTransferProperties(),
    factories.LockExpiredProperties(),
    factories.UnlockProperties(),
)
messages = [factories.create(factory) for factory in message_factories]

# TODO Handle these with factories once #5091 is implemented
messages.append(
    Delivered(
        delivered_message_identifier=factories.make_message_identifier(),
        signature=factories.make_signature(),
    )
)
messages.append(
    Processed(
        message_identifier=factories.make_message_identifier(),
        signature=factories.make_signature(),
    )
)
messages.append(
    RevealSecret(
        message_identifier=factories.make_message_identifier(),
        secret=factories.make_secret(),
        signature=factories.make_signature(),
    )
)
messages.append(
    SecretRequest(
        message_identifier=factories.make_message_identifier(),
        payment_identifier=factories.make_payment_id(),
        secrethash=factories.make_secret_hash(),
        amount=factories.make_payment_amount(),
        expiration=factories.make_block_expiration_number(),
        signature=factories.make_signature(),
    )
)
messages.append(
    WithdrawRequest(
        message_identifier=factories.make_message_identifier(),
        chain_id=factories.make_chain_id(),
        token_network_address=factories.make_token_network_address(),
        channel_identifier=factories.make_channel_identifier(),
        participant=factories.make_address(),
        total_withdraw=factories.make_withdraw_amount(),
        nonce=factories.make_nonce(),
        expiration=factories.make_block_expiration_number(),
        signature=factories.make_signature(),
    )
)
messages.append(
    WithdrawConfirmation(
        message_identifier=factories.make_message_identifier(),
        chain_id=factories.make_chain_id(),
        token_network_address=factories.make_token_network_address(),
        channel_identifier=factories.make_channel_identifier(),
        participant=factories.make_address(),
        total_withdraw=factories.make_withdraw_amount(),
        nonce=factories.make_nonce(),
        expiration=factories.make_block_expiration_number(),
        signature=factories.make_signature(),
    )
)
messages.append(
    WithdrawExpired(
        message_identifier=factories.make_message_identifier(),
        chain_id=factories.make_chain_id(),
        token_network_address=factories.make_token_network_address(),
        channel_identifier=factories.make_channel_identifier(),
        participant=factories.make_address(),
        total_withdraw=factories.make_withdraw_amount(),
        nonce=factories.make_nonce(),
        expiration=factories.make_block_expiration_number(),
        signature=factories.make_signature(),
    )
)
messages.append(
    PFSCapacityUpdate(
        canonical_identifier=factories.make_canonical_identifier(),
        updating_participant=factories.make_address(),
        other_participant=factories.make_address(),
        updating_nonce=factories.make_nonce(),
        other_nonce=factories.make_nonce(),
        updating_capacity=factories.make_token_amount(),
        other_capacity=factories.make_token_amount(),
        reveal_timeout=factories.make_block_timeout(),
        signature=factories.make_signature(),
    )
)
messages.append(
    PFSFeeUpdate(
        canonical_identifier=factories.make_canonical_identifier(),
        updating_participant=factories.make_address(),
        fee_schedule=factories.create(factories.FeeScheduleStateProperties()),
        timestamp=datetime(2000, 1, 1),
        signature=factories.make_signature(),
    )
)
messages.append(
    RequestMonitoring(
        reward_amount=factories.make_token_amount(),
        balance_proof=SignedBlindedBalanceProof.from_balance_proof_signed_state(
            factories.create(factories.BalanceProofSignedStateProperties())
        ),
        monitoring_service_contract_address=factories.make_monitoring_service_address(),
        non_closing_participant=factories.make_address(),
        non_closing_signature=factories.make_signature(),
        signature=factories.make_signature(),
    )
)


@dataclass
class ClassWithGraphObject:
    graph: Graph


@dataclass
class ClassWithInt:
    value: int


def test_decode_with_unknown_type():
    test_str = """{"_type": "some.non.existent.package"}"""
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize(test_str)

    test_str = """{"_type": "raiden.tests.NonExistentClass"}"""
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize(test_str)

    test_str = """{"_type": "NonExistentClass"}"""
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize(test_str)


@pytest.mark.parametrize("input_value", ["[", b"\x00"])
def test_deserialize_invalid_json(input_value):
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize(input_value)


def test_deserialize_wrong_type():
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize("[]")


def test_deserialize_missing_attribute():
    test_input = json.dumps({"_type": f"{ClassWithInt.__module__}.ClassWithInt"})
    with pytest.raises(SerializationError):
        JSONSerializer.deserialize(test_input)


def test_serialize_wrong_type():
    with pytest.raises(SerializationError):
        JSONSerializer.serialize([])


def test_serialize_missing_attribute():
    instance = ClassWithInt(1)
    instance.value = b"a"

    with pytest.raises(SerializationError):
        JSONSerializer.serialize(instance)


def test_serialization_networkx_graph():
    p1 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4C")
    p2 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4D")
    p3 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4E")
    p4 = to_canonical_address("0x5522070585a1a275631ba69c444ac0451AA9Fe4F")

    e = [(p1, p2), (p2, p3), (p3, p4)]
    graph = Graph(e)
    instance = ClassWithGraphObject(graph)

    data = JSONSerializer.serialize(instance)
    restored_instance = JSONSerializer.deserialize(data)

    assert instance.graph.edges == restored_instance.graph.edges


def test_actioninitchain_restore():
    """ ActionInitChain *must* restore the previous pseudo random generator
    state.

    Message identifiers are used for confirmation messages, e.g. delivered and
    processed messages, therefore it's important for each message identifier to
    not collide with a previous identifier, for this reason the PRNG is used.

    Additionally, during restarts the state changes are reapplied, and it's
    really important for the re-execution of the state changes to be
    deterministic, otherwise undefined behavior may happen. For this reason the
    state of the PRNG must be restored.

    If the above is not respected, the message ids generated during restart
    will not match the previous IDs and the message queues won't be properly
    cleared up.
    """
    pseudo_random_generator = random.Random()
    block_number = 577
    our_address = factories.make_address()
    chain_id = 777

    original_obj = state_change.ActionInitChain(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(JSONSerializer.serialize(original_obj))

    assert original_obj == decoded_obj


def test_chainstate_restore():
    pseudo_random_generator = random.Random()
    block_number = 577
    our_address = factories.make_address()
    chain_id = 777

    original_obj = state.ChainState(
        pseudo_random_generator=pseudo_random_generator,
        block_number=block_number,
        block_hash=factories.make_block_hash(),
        our_address=our_address,
        chain_id=chain_id,
    )

    decoded_obj = JSONSerializer.deserialize(JSONSerializer.serialize(original_obj))

    assert original_obj == decoded_obj


def test_encoding_and_decoding():
    for message in messages:
        serialized = MessageSerializer.serialize(message)
        deserialized = MessageSerializer.deserialize(serialized)
        assert deserialized == message


def test_bad_messages():
    "SerializationErrors should be raised on all kinds of wrong messages"
    for message in ["{}", "[]", '"foo"', "123"]:
        with pytest.raises(SerializationError):
            MessageSerializer.deserialize(message)


def test_message_identical() -> None:
    """ Will fail if the messages changed since the committed version

    If you intend to change the serialized messages, then update the messages
    on disc (see comment inside test). This test exists only to prevent
    accidental breaking of compatibility.

    If many values change in unexpected ways, that might have to do with the
    pseudo-random initialization of the messages (see random.seed() above).
    """
    signer = LocalSigner(bytes(range(32)))
    for message in messages:
        # The messages contain only random signatures. We don't want to test
        # only the serialization itself, but also prevent accidental changes of
        # the signature. To do this, we have to create proper signatures.
        message.sign(signer)

        filename = os.path.join(
            os.path.dirname(__file__), "serialized_messages", message.__class__.__name__ + ".json"
        )

        # Uncomment this for one run if you intentionally changed the message
        # with open(filename, "w") as f:
        #     json_msg = MessageSerializer.serialize(message)
        #     # pretty print for more readable diffs
        #     json_msg = json.dumps(json.loads(json_msg), indent=4, sort_keys=True)
        #     f.write(json_msg)

        with open(filename) as f:
            saved_message_dict = JSONSerializer.deserialize(f.read())

        # The assert output is more readable when we used dicts than with plain JSON
        message_dict = JSONSerializer.deserialize(MessageSerializer.serialize(message))
        assert message_dict == saved_message_dict


def test_hashing():
    """All messages must be hashable for de-duplication to work."""
    for message in messages:
        assert hash(message), "hashing failed"
