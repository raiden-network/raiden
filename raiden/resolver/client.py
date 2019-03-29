import json
import logging
import requests
from eth_utils import to_bytes, to_hex

from raiden.raiden_service import RaidenService
from raiden.transfer.mediated_transfer.events import SendSecretRequest
from raiden.transfer.mediated_transfer.state_change import ReceiveSecretReveal


def run():
    # This code is used to check the resolver server. It is not used in runtime.
    url = "http://localhost:8000"
    request = {"secret_hash": "29c7d166c11e15e521bb8ec7214ffd3d73cdd0be49c95dcb6eb8e17f958c58ce"}
    response = requests.post(url, json=request)

    assert response is not None
    if response.status_code != 200:
        print('Bad response from ', url, response.status_code, response.reason)
    else:
        assert response.status_code == 200
        print(response.text)
        print(json.loads(response.text)['secret'])
        print(to_bytes(hexstr=json.loads(response.text)['secret']))


def reveal_secret_with_resolver(
    raiden: RaidenService,
    secret_request_event: SendSecretRequest,
) -> bool:
    try:
        if raiden.config['resolver_endpoint'] is None:
            return False

        request = {
            "secret_hash": to_hex(secret_request_event.secrethash)[2:],
            "amount": secret_request_event.amount,
            "payment_identifier": secret_request_event.payment_identifier,
            "payment_sender": to_hex(secret_request_event.recipient)[2:],
            "expiration": secret_request_event.expiration,
            "payment_recipient": to_hex(raiden.address)[2:],
            "reveal_timeout": raiden.config['reveal_timeout'],
            "settle_timeout": raiden.config['settle_timeout'],
        }
        response = requests.post(raiden.config['resolver_endpoint'], json=request)

        if response is None or response.status_code != 200:
            return False

        state_change = ReceiveSecretReveal(
            to_bytes(hexstr=json.loads(response.text)['secret']),
            secret_request_event.recipient,
        )
        raiden.handle_and_track_state_change(state_change)
        return True

    except Exception:
        return False


if __name__ == '__main__':
    logging.basicConfig()
    run()
