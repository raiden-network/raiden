import json
from http import HTTPStatus
from typing import TYPE_CHECKING

import gevent
import requests
import structlog
from eth_utils import to_bytes, to_hex

from raiden.storage.wal import WriteAheadLog
from raiden.transfer import views
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal
from raiden.transfer.state import ChainState
from raiden.utils import Secret

if TYPE_CHECKING:
    # pylint: disable=unused-import
    from raiden.raiden_service import RaidenService


log = structlog.get_logger(__name__)


def reveal_secret_with_resolver(
    raiden: "RaidenService", chain_state: ChainState, secret_request_event: SendSecretRequest
) -> bool:

    resolver_endpoint = raiden.config.get("resolver_endpoint")
    if not resolver_endpoint:
        return False

    log.debug("Using resolver to fetch secret", resolver_endpoint=resolver_endpoint)

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
        "chain_id": chain_state.chain_id,
    }

    # loop until we get a valid response from the resolver or until timeout
    while True:
        current_state = views.state_from_raiden(raiden)

        if secret_request_event.expiration < current_state.block_number:
            log.debug(
                "Stopped using resolver, transfer expired", resolver_endpoint=resolver_endpoint
            )
            return False

        response = None

        try:
            # before calling resolver, update block height
            request["chain_height"] = chain_state.block_number
            response = requests.post(resolver_endpoint, json=request)
        except requests.exceptions.RequestException:
            pass

        # no response means the resolver could not be reached and we should try again
        if response is not None:
            if response.status_code == HTTPStatus.OK:
                # request succeeded so we can break the loop and use the secret
                break
            elif response.status_code == HTTPStatus.SERVICE_UNAVAILABLE:
                # treat SERVICE UNAVAILABLE as if the resolver could not be reached and try again
                pass
            else:
                # on any other status code, treat the request as having failed and return False
                return False
        gevent.sleep(5)

    log.debug(
        "Got secret from resolver, dispatching secret reveal", resolver_endpoint=resolver_endpoint
    )
    state_change = ReceiveSecretReveal(
        sender=secret_request_event.recipient,
        secret=Secret(to_bytes(hexstr=json.loads(response.content)["secret"])),
    )
    raiden.handle_and_track_state_changes([state_change])
    return True
