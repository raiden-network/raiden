from typing import List
from unittest import mock

import requests
from eth_utils import to_normalized_address, to_hex

from pathfinder.api.rest import ServiceApi
from pathfinder.model.balance_proof import BalanceProof
from pathfinder.model.lock import Lock
from pathfinder.token_network import TokenNetwork
from pathfinder.utils.types import Address
from pathfinder.tests.fixtures.network_service import forge_fee_signature


#
# tests for /balance endpoint
#
def test_put_balance(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address]
):
    url = api_url + '/{}/123/balance'.format(token_network_addresses[0])

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


def test_put_balance_sync_check(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address]
):
    url = api_url + '/{}/12/balance'.format(token_network_addresses[0])

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

    # path channel id and BP channel id are not equal
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith(
        'The channel id from the balance proof (123) and '
        'the request (12) do not match'
    )

    body = dict(
        balance_proof=dict(
            nonce=1,
            transferred_amount=3,
            locksroot='',
            channel_identifier=12,
            token_network_address=token_network_addresses[1],
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

    # now the network address doesn't match
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('The token network address from the balance proof')


def test_put_balance_path_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    body = dict()

    url = api_url + '/1234abc/1/balance'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid token network address: 1234abc'

    url = api_url + '/df173a5173c3d0ae5ba11dae84470c5d3f1a8413/1/balance'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        'df173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413/1/balance'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        '0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0x0000000000000000000000000000000000000000/1/balance'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Unsupported token network: {}'.format(
        '0x0000000000000000000000000000000000000000'
    )

    url = api_url + '/{}/abc/balance'.format(token_network_addresses[0])
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Channel Id is not an integer: {}'.format(
        'abc'
    )


def test_put_balance_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    url = api_url + '/{}/123/balance'.format(token_network_addresses[0])

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
    assert response.json()['error'].startswith('The token network address from the balance proof')


#
# tests for /fee endpoint
#
def test_put_fee(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address],
    private_keys: List[str],
):
    url = api_url + '/{}/123/fee'.format(token_network_addresses[0])

    token_networks[0].update_fee = mock.Mock(return_value=None)

    fee = 0.02
    signature = forge_fee_signature(private_keys[0], fee)

    body = dict(
        fee=str(fee),
        signature=to_hex(signature)
    )

    response = requests.put(url, json=body)
    assert response.status_code == 200
    token_networks[0].update_fee.assert_called_once()
    call_args = token_networks[0].update_fee.call_args[0]
    fee_arg: str = call_args[1]
    signature_arg: str = call_args[2]

    assert fee_arg == b'0.02'  # this gets converted to bytes in the rest api
    assert signature_arg == signature


def test_put_fee_path_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    body = dict()

    url = api_url + '/1234abc/1/fee'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid token network address: 1234abc'

    url = api_url + '/df173a5173c3d0ae5ba11dae84470c5d3f1a8413/1/fee'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        'df173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413/1/fee'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        '0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0x0000000000000000000000000000000000000000/1/fee'
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Unsupported token network: {}'.format(
        '0x0000000000000000000000000000000000000000'
    )

    url = api_url + '/{}/abc/fee'.format(token_network_addresses[0])
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == 'Channel Id is not an integer: {}'.format(
        'abc'
    )


#
# tests for /paths endpoint
#
def test_get_paths_validation(
    api_sut: ServiceApi,
    api_url: str,
    initiator_address: str,
    target_address: str,
    token_network_addresses: List[Address]
):
    base_url = api_url + '/{}/paths'.format(token_network_addresses[0])

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


def test_get_paths_path_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    url = api_url + '/1234abc/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid token network address: 1234abc'

    url = api_url + '/df173a5173c3d0ae5ba11dae84470c5d3f1a8413/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        'df173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Token network address not checksummed: {}'.format(
        '0xdf173a5173c3d0ae5ba11dae84470c5d3f1a8413'
    )

    url = api_url + '/0x0000000000000000000000000000000000000000/paths'
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Unsupported token network: {}'.format(
        '0x0000000000000000000000000000000000000000'
    )


def test_get_paths(
    api_sut: ServiceApi,
    api_url: str,
    addresses: List[Address],
    token_network_addresses: List[Address]
):
    base_url = api_url + '/{}/paths'.format(token_network_addresses[0])

    url = base_url + '?from={}&to={}&value=10&num_paths=3'.format(
        addresses[0],
        addresses[2]
    )
    response = requests.get(url)
    assert response.status_code == 200
    paths = response.json()['result']
    assert len(paths) == 2
    assert paths == [
        [addresses[0], addresses[1], addresses[2]],
        [addresses[0], addresses[1], addresses[4], addresses[3], addresses[2]]
    ]

    # there is no connection between 0 and 5, this should return an error
    url = base_url + '?from={}&to={}&value=10&num_paths=3'.format(
        addresses[0],
        addresses[5]
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'].startswith('No suitable path found for transfer from')
