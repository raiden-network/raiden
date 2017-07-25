# -*- coding: utf-8 -*-
from coincurve import PrivateKey
from hypothesis.strategies import (
    composite,
    binary,
    integers,
)

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import DirectTransfer
from raiden.utils import privatekey_to_address


privatekeys = binary(min_size=32, max_size=32)
identifier = integers(min_value=0, max_value=UINT64_MAX)
nonce = integers(min_value=1, max_value=UINT64_MAX)
transferred_amount = integers(min_value=0, max_value=UINT256_MAX)


@composite
def direct_transfer(draw, token, recipient, locksroot):
    return DirectTransfer(
        draw(identifier),
        draw(nonce),
        draw(token),
        draw(transferred_amount),
        draw(recipient),
        draw(locksroot),
    )


@composite
def signed_transfer(draw, transfer_strategy, privatekeys_strategy):
    transfer = draw(transfer_strategy)
    privatekey = draw(privatekeys_strategy)

    transfer.sign(
        PrivateKey(privatekey),
        privatekey_to_address(privatekey),
    )

    return transfer
