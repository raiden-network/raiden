# -*- coding: utf-8 -*-
import pytest

from raiden.messages import (
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.tests.utils.factories import (
    HOP1,
    HOP1_KEY,
    UNIT_HASHLOCK,
    UNIT_SECRET,
    make_address,
)
from raiden.tests.utils.messages import make_refund_transfer
from raiden.tests.utils.transfer import sign_and_inject


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_hashlocktransfer_unknown(raiden_network, token_addresses):
    app0 = raiden_network[0]
    token_address = token_addresses[0]

    other_key = HOP1_KEY
    other_address = HOP1
    amount = 10
    refund_transfer_message = make_refund_transfer(
        identifier=1,
        nonce=1,
        token=token_address,
        channel=other_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_HASHLOCK,
        amount=amount,
        hashlock=UNIT_HASHLOCK,
    )
    sign_and_inject(refund_transfer_message, other_key, other_address, app0)

    secret = Secret(
        identifier=1,
        nonce=1,
        channel=make_address(),
        transferred_amount=amount,
        locksroot=UNIT_HASHLOCK,
        secret=UNIT_SECRET,
    )
    sign_and_inject(secret, other_key, other_address, app0)

    secret_request_message = SecretRequest(1, UNIT_HASHLOCK, 1)
    sign_and_inject(secret_request_message, other_key, other_address, app0)

    reveal_secret_message = RevealSecret(UNIT_SECRET)
    sign_and_inject(reveal_secret_message, other_key, other_address, app0)
