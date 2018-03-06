from typing import List
from unittest import mock

import requests
from eth_utils import to_normalized_address

from pathfinder.api.rest import ServiceApi
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.lock import Lock
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import Address


def test_put_balance(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address]
):
    url = api_url + '/balance'

    token_networks[0].update_balance = mock.Mock(return_value=None)

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=123,
            token_network_address=token_network_addresses[0],
            chain_id=321,
            additional_hash='',
            signature=''
        ),
        locks=[
            dict(
                amount_locked=4,
                expiration=107,
                hashlock=''
            )
        ]
    )

    response = requests.put(url, json=body)
    assert response.status_code == 200
    token_networks[0].update_balance.assert_called_once()
    call_args = token_networks[0].update_balance.call_args[0]
    balance_proof: BalanceProof = call_args[0]
    locks: List[Lock] = call_args[1]
    assert balance_proof.nonce == 1
    assert balance_proof.transferred_amount == 3
    assert balance_proof.locksroot == b''
    assert balance_proof.channel_id == 123
    assert balance_proof.token_network_address == token_network_addresses[0]
    assert balance_proof.chain_id == 321
    assert balance_proof.additional_hash == b''
    assert balance_proof.signature == b''
    assert len(locks) == 1
    assert locks[0].amount_locked == 4
    assert locks[0].expiration == 107
    assert locks[0].hashlock == b''


def test_put_balance_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    url = api_url + '/balance'

    body = dict()
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'No balance proof specified.'

    body = dict(
        balance_proof={},
        locks=[]
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('Invalid balance proof format. Missing parameter:')

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=123,
            token_network_address=to_normalized_address(token_network_addresses[0]),
            chain_id=321,
            additional_hash='',
            signature=''
        ),
        locks=[]
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith(
        'Missing or invalid checksum on token network address.'
    )

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=123,
            token_network_address=token_network_addresses[0],
            chain_id=321,
            additional_hash='',
            signature=''
        )
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('No lock list specified.')

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=123,
            token_network_address=token_network_addresses[0],
            chain_id=321,
            additional_hash='',
            signature=''
        ),
        locks={}
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('No lock list specified.')

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=123,
            token_network_address='0xDeaDbeefdEAdbeefdEadbEEFdeadbeEFdEaDbeeF',
            chain_id=321,
            additional_hash='',
            signature=''
        ),
        locks=[]
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('Unsupported token network:')


def test_get_paths_validation(
    api_sut: ServiceApi,
    api_url: str,
    initiator_address: str,
    target_address: str
):
    base_url = api_url + '/paths'

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
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Initiator address not checksummed: {}'.format(
        to_normalized_address(initiator_address)
    )

    url = base_url + '?from={}&to={}&value=5&num_paths=3'.format(
        initiator_address,
        to_normalized_address(target_address)
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Target address not checksummed: {}'.format(
        to_normalized_address(target_address)
    )

    url = base_url + '?from={}&to={}&value=-10&num_paths=3'.format(
        initiator_address,
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Payment value must be non-negative: -10'

    url = base_url + '?from={}&to={}&value=10&num_paths=-1'.format(
        initiator_address,
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Number of paths must be positive: -1'
