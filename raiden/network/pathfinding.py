import requests

from raiden.constants import DEFAULT_HTTP_REQUEST_TIMEOUT
from raiden.exceptions import ServiceRequestFailed
from raiden.utils import typing
from raiden_contracts.utils.proofs import sign_one_to_n_iou


def get_pfs_info(url: str) -> typing.Optional[typing.Dict]:
    try:
        return requests.get(f'{url}/api/v1/info', timeout=DEFAULT_HTTP_REQUEST_TIMEOUT).json()
    except requests.exceptions.RequestException:
        return None


def make_iou(
        config: typing.Dict[str, typing.Any],
        our_address: typing.Address,
        privkey: bytes,
        block_number: typing.BlockNumber,
) -> typing.Dict:
    expiration = block_number + config['pathfinding_iou_timeout']

    iou = dict(
        sender=our_address,
        receiver=config['pathfinding_eth_address'],
        amount=config['pathfinding_max_fee'],
    )

    iou.update(
        expiration_block=expiration,
        signature=sign_one_to_n_iou(privatekey=privkey, expiration=expiration, **iou),
    )

    return iou


def query_paths(
        service_config: typing.Dict[str, typing.Any],
        our_address: typing.Address,
        privkey: bytes,
        current_block_number: typing.BlockNumber,
        token_network_address: typing.Union[typing.TokenNetworkAddress, typing.TokenNetworkID],
        route_from: typing.InitiatorAddress,
        route_to: typing.TargetAddress,
        value: typing.TokenAmount,
):
    max_paths = service_config['pathfinding_max_paths']
    url = service_config['pathfinding_service_address']
    payload = {'from': route_from, 'to': route_to, 'value': value, 'max_paths': max_paths}

    payload.update(make_iou(service_config, our_address, privkey, current_block_number))

    try:
        response = requests.post(
            f'{url}/api/v1/{token_network_address}/paths',
            data=payload,
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        )
    except requests.RequestException:
        raise ServiceRequestFailed(
            'Could not connect to Pathfinding Service',
            dict(parameters=payload, exc_info=True),
        )

    if response.status_code != 200:
        info = {'error_code': response.status_code}
        try:
            error = response.json().get('errors')
            if error is not None:
                info['pfs_error'] = error
        except ValueError:  # invalid json
            pass
        raise ServiceRequestFailed('Pathfinding service returned error code', info)

    try:
        return response.json()['result']
    except KeyError:
        raise ServiceRequestFailed(
            "Answer from pathfinding service not understood ('result' field missing)",
            dict(response=response.json()),
        )
    except ValueError:
        raise ServiceRequestFailed(
            'Pathfinding service returned invalid json',
            dict(response_text=response.text, exc_info=True),
        )
