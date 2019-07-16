import random

import pytest

from raiden.constants import EMPTY_SIGNATURE, UINT64_MAX
from raiden.messages.transfers import RevealSecret, SecretRequest, Unlock
from raiden.tests.utils import factories
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.factories import HOP1_KEY, UNIT_CHAIN_ID, UNIT_SECRET, UNIT_SECRETHASH
from raiden.tests.utils.transfer import sign_and_inject
from raiden.transfer import views
from raiden.utils.signer import LocalSigner


@pytest.mark.parametrize("number_of_nodes", [1])
@pytest.mark.parametrize("channels_per_node", [0])
def test_receive_secrethashtransfer_unknown(raiden_network, token_addresses):
    raise_on_failure(
        raiden_network,
        run_test_receive_secrethashtransfer_unknown,
        raiden_network=raiden_network,
        token_addresses=token_addresses,
    )


def run_test_receive_secrethashtransfer_unknown(raiden_network, token_addresses):
    app0 = raiden_network[0]
    token_address = token_addresses[0]

    token_network_address = views.get_token_network_address_by_token_address(
        views.state_from_app(app0), app0.raiden.default_registry.address, token_address
    )

    other_key = HOP1_KEY
    other_signer = LocalSigner(other_key)
    canonical_identifier = factories.make_canonical_identifier(
        token_network_address=token_network_address
    )

    amount = 10
    refund_transfer_message = factories.create(
        factories.RefundTransferProperties(
            payment_identifier=1,
            nonce=1,
            token=token_address,
            canonical_identifier=canonical_identifier,
            transferred_amount=amount,
            recipient=app0.raiden.address,
            locksroot=UNIT_SECRETHASH,
            amount=amount,
            secret=UNIT_SECRET,
        )
    )
    sign_and_inject(refund_transfer_message, other_signer, app0)

    unlock = Unlock(
        chain_id=UNIT_CHAIN_ID,
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        nonce=1,
        channel_identifier=canonical_identifier.channel_identifier,
        token_network_address=token_network_address,
        transferred_amount=amount,
        locked_amount=0,
        locksroot=UNIT_SECRETHASH,
        secret=UNIT_SECRET,
        signature=EMPTY_SIGNATURE,
    )
    sign_and_inject(unlock, other_signer, app0)

    secret_request_message = SecretRequest(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        secrethash=UNIT_SECRETHASH,
        amount=1,
        expiration=refund_transfer_message.lock.expiration,
        signature=EMPTY_SIGNATURE,
    )
    sign_and_inject(secret_request_message, other_signer, app0)

    reveal_secret_message = RevealSecret(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=UNIT_SECRET,
        signature=EMPTY_SIGNATURE,
    )
    sign_and_inject(reveal_secret_message, other_signer, app0)
