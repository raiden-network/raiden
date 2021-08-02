from unittest.mock import patch

import pytest

from raiden.exceptions import InvalidSecret
from raiden.tests.utils.detect_failure import raise_on_failure
from raiden.tests.utils.events import search_for_item
from raiden.tests.utils.network import CHAIN
from raiden.tests.utils.transfer import has_unlock_failure, transfer
from raiden.transfer.mediated_transfer.events import (
    EventUnlockClaimSuccess,
    EventUnlockSuccess,
    SendSecretRequest,
    SendSecretReveal,
)
from raiden.utils.typing import PaymentAmount, PaymentID
from raiden.waiting import wait_until


@raise_on_failure
@pytest.mark.parametrize("channels_per_node", [CHAIN])
@pytest.mark.parametrize("number_of_nodes", [3])
def test_mediated_transfer_events(raiden_network, number_of_nodes, token_addresses, network_wait):
    app0, app1, app2 = raiden_network
    token_address = token_addresses[0]

    amount = 10
    with patch("raiden.message_handler.decrypt_secret", side_effect=InvalidSecret):
        transfer(
            initiator_app=app0,
            target_app=app2,
            token_address=token_address,
            amount=PaymentAmount(amount),
            identifier=PaymentID(1),
            timeout=network_wait * number_of_nodes,
            routes=[[app0, app1, app2]],
        )

    def test_initiator_events():
        assert not has_unlock_failure(app0)
        initiator_events = app0.wal.storage.get_events()
        secret_reveal = search_for_item(initiator_events, SendSecretReveal, {})
        unlock_success = search_for_item(initiator_events, EventUnlockSuccess, {})
        return secret_reveal and unlock_success

    assert wait_until(test_initiator_events, network_wait)

    def test_mediator_events():
        assert not has_unlock_failure(app1)
        mediator_events = app1.wal.storage.get_events()
        unlock_success = search_for_item(mediator_events, EventUnlockSuccess, {})
        unlock_claim_success = search_for_item(mediator_events, EventUnlockClaimSuccess, {})
        return unlock_success and unlock_claim_success

    assert wait_until(test_mediator_events, network_wait)

    def test_target_events():
        assert not has_unlock_failure(app2)
        target_events = app2.wal.storage.get_events()
        return (
            search_for_item(target_events, SendSecretRequest, {})
            and search_for_item(target_events, SendSecretReveal, {})
            and search_for_item(target_events, EventUnlockClaimSuccess, {})
        )

    assert wait_until(test_target_events, network_wait)
