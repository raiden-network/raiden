from typing import List

import requests
import socket
import pathfinder
import pkg_resources
from eth_utils import to_normalized_address

from pathfinder.api.rest import ServiceApi
from pathfinder.model import TokenNetwork
from raiden_libs.types import Address

ID_12 = 12
ID_123 = 123


#
# tests for /paths endpoint
#
def test_get_paths_validation(
    api_sut: ServiceApi,
    api_url: str,
    initiator_address: str,
    target_address: str,
    token_network_model: TokenNetwork,
):
    base_url = api_url + f'/{token_network_model.address}/paths'

    url = base_url
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'].startswith('Required parameters:')

    url = base_url + '?from=notanaddress&to={}&value=5&num_paths=3'.format(target_address)
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid initiator address: notanaddress'

    url = base_url + '?from={}&to=notanaddress&value=5&num_paths=3'.format(initiator_address)
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid target address: notanaddress'

    url = base_url + '?from={}&to={}&value=5&num_paths=3'.format(
        to_normalized_address(initiator_address),
        target_address,
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Initiator address not checksummed: {}'.format(
        to_normalized_address(initiator_address),
    )

    url = base_url + '?from={}&to={}&value=5&num_paths=3'.format(
        initiator_address,
        to_normalized_address(target_address),
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Target address not checksummed: {}'.format(
        to_normalized_address(target_address),
    )

    url = base_url + '?from={}&to={}&value=-10&num_paths=3'.format(
        initiator_address,
        target_address,
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Payment value must be non-negative: -10'

    url = base_url + '?from={}&to={}&value=10&num_paths=-1'.format(
        initiator_address,
        target_address,
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Number of paths must be positive: -1'


def test_get_paths_path_validation(
    api_sut: ServiceApi,
    api_url: str,
):
    url = api_url + '/1234abc/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid token network address: 1234abc'

    url = api_url + '/df173a5173c3d0ae5ba11dae84470c5d3f1a8413/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        'df173a5173c3d0ae5ba11dae84470c5d3f1a8413',
    )

    url = api_url + '/0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        '0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413',
    )

    url = api_url + '/0x0000000000000000000000000000000000000000/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Unsupported token network: {}'.format(
        '0x0000000000000000000000000000000000000000',
    )


def test_get_paths(
    api_sut: ServiceApi,
    api_url: str,
    addresses: List[Address],
    token_network_model: TokenNetwork,
):
    base_url = api_url + f'/{token_network_model.address}/paths'

    url = base_url + '?from={}&to={}&value=10&num_paths=3'.format(
        addresses[0],
        addresses[2],
    )
    response = requests.get(url)
    assert response.status_code == 200
    paths = response.json()['result']
    assert len(paths) == 3
    assert paths == [
        {
            'path': [addresses[0], addresses[2]],
            'estimated_fee': 1000,
        },
        {
            'path': [addresses[0], addresses[1], addresses[2]],
            'estimated_fee': 2000,
        },
        {
            'path': [addresses[0], addresses[1], addresses[4], addresses[3], addresses[2]],
            'estimated_fee': 4000,
        },
    ]

    # there is no connection between 0 and 5, this should return an error
    url = base_url + '?from={}&to={}&value=10&num_paths=3'.format(
        addresses[0],
        addresses[5],
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'].startswith('No suitable path found for transfer from')


#
# tests for /info endpoint
#

def test_get_info(
    api_sut: ServiceApi,
    api_url: str,
):
    url = api_url + f'/info'

    response = requests.get(url)
    assert response.status_code == 200
    assert response.json() == {
            'ip': socket.gethostbyname(socket.gethostname()),
            'settings': 'PLACEHOLDER',
            'version': pkg_resources.require(pathfinder.__name__)[0].version,
            'operator': 'Dominik',
            'message': 'This is for Paul'
        }
