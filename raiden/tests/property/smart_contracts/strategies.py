# -*- coding: utf-8 -*-
from hypothesis.strategies import (
    composite,
    binary,
    integers,
)

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.messages import DirectTransfer


privatekeys = binary(min_size=32, max_size=32)
identifier = integers(min_value=0, max_value=UINT64_MAX)
nonce = integers(min_value=1, max_value=UINT64_MAX)
transferred_amount = integers(min_value=0, max_value=UINT256_MAX)


@composite
def direct_transfer(draw, token, channel, recipient, locksroot):
    return DirectTransfer(
        draw(identifier),
        draw(nonce),
        draw(token),
        draw(channel),
        draw(transferred_amount),
        draw(recipient),
        draw(locksroot),
    )
