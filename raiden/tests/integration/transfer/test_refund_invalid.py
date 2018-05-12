# -*- coding: utf-8 -*-
import random

import pytest

from raiden.constants import UINT64_MAX
from raiden.messages import (
    RevealSecret,
    Secret,
    SecretRequest,
)
from raiden.tests.utils.factories import (
    HOP1,
    HOP1_KEY,
    UNIT_SECRETHASH,
    UNIT_SECRET,
    make_address,
)
from raiden.tests.utils.messages import make_refund_transfer
from raiden.tests.utils.transfer import sign_and_inject


@pytest.mark.parametrize('number_of_nodes', [1])
@pytest.mark.parametrize('channels_per_node', [0])
def test_receive_secrethashtransfer_unknown(raiden_network, token_addresses):
    app0 = raiden_network[0]
    token_address = token_addresses[0]

    other_key = HOP1_KEY
    other_address = HOP1
    amount = 10
    refund_transfer_message = make_refund_transfer(
        payment_identifier=1,
        nonce=1,
        registry_address=app0.raiden.default_registry.address,
        token=token_address,
        channel=other_address,
        transferred_amount=amount,
        recipient=app0.raiden.address,
        locksroot=UNIT_SECRETHASH,
        amount=amount,
        secrethash=UNIT_SECRETHASH,
    )
    sign_and_inject(refund_transfer_message, other_key, other_address, app0)

    secret = Secret(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        nonce=1,
        channel=make_address(),
        transferred_amount=amount,
        locked_amount=0,
        locksroot=UNIT_SECRETHASH,
        secret=UNIT_SECRET,
    )
    sign_and_inject(secret, other_key, other_address, app0)

    secret_request_message = SecretRequest(
        message_identifier=random.randint(0, UINT64_MAX),
        payment_identifier=1,
        secrethash=UNIT_SECRETHASH,
        amount=1,
    )
    sign_and_inject(secret_request_message, other_key, other_address, app0)

    reveal_secret_message = RevealSecret(
        message_identifier=random.randint(0, UINT64_MAX),
        secret=UNIT_SECRET,
    )
    sign_and_inject(reveal_secret_message, other_key, other_address, app0)
