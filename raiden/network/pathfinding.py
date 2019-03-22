import json
import random
import sys
from typing import Optional

import click
import requests
import structlog
from eth_utils import to_checksum_address, to_hex

from raiden.constants import DEFAULT_HTTP_REQUEST_TIMEOUT, RoutingMode
from raiden.exceptions import ServiceRequestFailed
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.utils import typing
from raiden_contracts.utils.proofs import sign_one_to_n_iou

log = structlog.get_logger(__name__)


def get_pfs_info(url: str) -> typing.Optional[typing.Dict]:
    try:
        response = requests.get(
            f'{url}/api/v1/info',
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        )
        return response.json()
    except (json.JSONDecodeError, requests.exceptions.RequestException):
        return None


def get_random_service(service_registry: ServiceRegistry) -> Optional[str]:
    latest_block_hash = service_registry.client.blockhash_from_blocknumber(
        'latest',
    )
    count = service_registry.service_count(block_identifier=latest_block_hash)
    if count == 0:
        return None
    index = random.SystemRandom().randint(0, count - 1)
    address = service_registry.get_service_address(
        block_identifier=latest_block_hash,
        index=index,
    )
    # We are using the same blockhash for both blockchain queries so the address
    # should exist for this query. Additionally at the moment there is no way for
    # services to be removed from the registry.
    assert address, 'address should exist for this index'
    return service_registry.get_service_url(
        block_identifier=latest_block_hash,
        service_hex_address=address,
    )


def configure_pfs(
        pfs_address: Optional[str],
        routing_mode: RoutingMode,
        service_registry,
) -> Optional[str]:
    """
    Take in the given pfs_address argument, the service registry and find out a
    pfs address to use.

    If pfs_address is None then basic routing must have been requested.
    If pfs_address is provided we use that.
    If pfs_address is 'auto' then we randomly choose a PFS address from the registry

    Returns the PFS url to use or None if we don't use the PFS and use basic routing
    """
    if routing_mode == RoutingMode.BASIC:
        msg = 'Not using path finding services, falling back to basic routing.'
        log.info(msg)
        click.secho(msg)
        return None

    msg = "With PFS routing mode we shouldn't get to configure pfs with pfs_address being None"
    assert pfs_address, msg
    if pfs_address == 'auto':
        assert service_registry, 'Should not get here without a service registry'
        pfs_address = get_random_service(service_registry)
        if pfs_address is None:
            click.secho(
                "The service registry has no registered path finding service "
                "and we don't use basic routing.",
            )
            sys.exit(1)

    pathfinding_service_info = get_pfs_info(pfs_address)
    if not pathfinding_service_info:
        click.secho(
            f'There is an error with the pathfinding service with address '
            f'{pfs_address}. Raiden will shut down.',
        )
        sys.exit(1)
    else:
        click.secho(
            f"'{pathfinding_service_info['message']}'. "
            f"You have chosen pathfinding operator '{pathfinding_service_info['operator']}' "
            f"with the running version '{pathfinding_service_info['version']}' "
            f"on chain_id: '{pathfinding_service_info['network_info']['chain_id']}."
            f"Requesting a path will cost you: '{pathfinding_service_info['price_info']}",
        )
        log.info('Using PFS', pfs_info=pathfinding_service_info)

    return pfs_address


def get_pfs_iou(
        url: str,
        token_network_address: typing.Union[typing.TokenNetworkAddress, typing.TokenNetworkID],
        **kwargs,
) -> typing.Optional[typing.Dict]:
    try:
        return requests.get(
            f'{url}/api/v1/{to_checksum_address(token_network_address)}/payment/iou',
            data=kwargs,
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        ).json().get('last_iou')
    except (requests.exceptions.RequestException, ValueError) as e:
        raise ServiceRequestFailed(str(e))


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
        signature=sign_one_to_n_iou(privatekey=to_hex(privkey), expiration=expiration, **iou),
    )

    return iou


def update_iou(
        iou: typing.Dict[str, typing.Any],
        privkey: bytes,
        added_amount: typing.TokenAmount = 0,
        expiration_block: typing.Optional[typing.BlockNumber] = None,
) -> typing.Dict[str, typing.Any]:

    iou['amount'] += added_amount
    if expiration_block:
        iou['expiration_block'] = expiration_block

    iou['signature'] = sign_one_to_n_iou(
        privatekey=to_hex(privkey),
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
        privkey: bytes,
        block_number: typing.BlockNumber,
) -> typing.Dict[str, typing.Any]:
    url = config['pathfinding_service_address']
    latest_iou = get_pfs_iou(url, token_network_address)
    if latest_iou is None:
        return make_iou(
            config=config,
            our_address=our_address,
            privkey=privkey,
            block_number=block_number,
        )
    else:
        added_amount = config['pathfinding_max_fee']
        return update_iou(iou=latest_iou, privkey=privkey, added_amount=added_amount)


def query_paths(
        service_config: typing.Dict[str, typing.Any],
        our_address: typing.Address,
        privkey: bytes,
        current_block_number: typing.BlockNumber,
        token_network_address: typing.Union[typing.TokenNetworkAddress, typing.TokenNetworkID],
        route_from: typing.InitiatorAddress,
        route_to: typing.TargetAddress,
        value: typing.TokenAmount,
) -> typing.List[typing.Dict[str, typing.Any]]:
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
            f'{url}/api/v1/{to_checksum_address(token_network_address)}/paths',
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
