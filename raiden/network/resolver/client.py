import json
from http import HTTPStatus
from typing import TYPE_CHECKING

import requests
from eth_utils import to_bytes, to_hex

from raiden.storage.wal import WriteAheadLog
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal
from raiden.utils import Secret

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService


def reveal_secret_with_resolver(
    raiden: "RaidenService", secret_request_event: SendSecretRequest
) -> bool:

    if "resolver_endpoint" not in raiden.config:
        return False

    assert isinstance(raiden.wal, WriteAheadLog), "RaidenService has not been started"
    current_state = raiden.wal.state_manager.current_state

    if current_state is None:
        return False

    task = current_state.payment_mapping.secrethashes_to_task[secret_request_event.secrethash]
    token = task.target_state.transfer.token

    request = {
        "token": to_hex(token),
        "secrethash": to_hex(secret_request_event.secrethash),
        "amount": secret_request_event.amount,
        "payment_identifier": secret_request_event.payment_identifier,
        "payment_sender": to_hex(secret_request_event.recipient),
        "expiration": secret_request_event.expiration,
        "payment_recipient": to_hex(raiden.address),
        "reveal_timeout": raiden.config["reveal_timeout"],
        "settle_timeout": raiden.config["settle_timeout"],
    }

    try:
        response = requests.post(raiden.config["resolver_endpoint"], json=request)
    except requests.exceptions.RequestException:
        return False

    if response is None or response.status_code != HTTPStatus.OK:
        return False

    state_change = ReceiveSecretReveal(
        sender=secret_request_event.recipient,
        secret=Secret(to_bytes(hexstr=json.loads(response.content)["secret"])),
    )
    raiden.handle_and_track_state_changes([state_change])
    return True
