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


def get_pfs_iou(
        url: str,
        token_network_address: typing.Union[typing.TokenNetworkAddress, typing.TokenNetworkID],
        **kwargs,
) -> typing.Optional[typing.Dict]:
    try:
        return requests.get(
            f'{url}/api/v1/{token_network_address}/payment/iou',
            data=kwargs,
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        ).json().get('last_iou')
    except (requests.exceptions.RequestException, ValueError) as e:
        raise ServiceRequestFailed(str(e))


def make_iou(
        config: typing.Dict[str, typing.Any],
        our_address: typing.Address,
        privkey: str,
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


def update_iou(
        iou: typing.Dict[str, typing.Any],
        privkey: str,
        added_amount: typing.TokenAmount = 0,
        expiration_block: typing.Optional[typing.BlockNumber] = None,
) -> typing.Dict[str, typing.Any]:

    iou['amount'] += added_amount
    if expiration_block:
        iou['expiration_block'] = expiration_block

    iou['signature'] = sign_one_to_n_iou(
        privatekey=privkey,
        expiration=iou['expiration_block'],
        sender=iou['sender'],
        receiver=iou['receiver'],
        amount=iou['amount'],
    )

    return iou


def create_current_iou(
        config: typing.Dict[str, typing.Any],
        token_network_address: typing.Union[typing.TokenNetworkAddress, typing.TokenNetworkID],
        our_address: typing.Address,
        privkey: str,
        block_number: typing.BlockNumber,
):
    url = config['pathfinding_service_address']
    latest_iou = get_pfs_iou(url, token_network_address)
    if latest_iou is None:
        return make_iou(config, our_address, privkey, block_number)
    else:
        added_amount = config['pathfinding_max_fee']
        return update_iou(latest_iou, privkey, added_amount=added_amount)


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

    payload.update(create_current_iou(
        config=service_config,
        token_network_address=token_network_address,
        our_address=our_address,
        privkey=privkey,
        block_number=current_block_number,
    ))

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
