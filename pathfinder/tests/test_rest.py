from typing import List, Dict
from unittest import mock

import requests
from eth_utils import to_normalized_address, encode_hex, is_same_address
from raiden_libs.utils.signing import sign_data, private_key_to_address
from raiden_libs.messages import FeeInfo, BalanceProof
from raiden_libs.types import Address, ChannelIdentifier

from pathfinder.api.rest import ServiceApi
from pathfinder.model import TokenNetwork


#
# tests for /balance endpoint
#
def test_put_balance(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address],
    private_keys: List[str],
):
    url = api_url + '/{}/123/balance'.format(token_network_addresses[0])

    token_networks[0].update_balance = mock.Mock(return_value=None)  # type: ignore

    balance_proof = BalanceProof(
        channel_identifier=123,
        token_network_address=token_network_addresses[0],
        nonce=1,
        chain_id=321,
        locksroot="0x%064x" % 0,
        transferred_amount=1,
        locked_amount=0,
        additional_hash="0x%064x" % 0,
    )
    balance_proof.signature = encode_hex(sign_data(private_keys[0], balance_proof.serialize_bin()))

    body = balance_proof.serialize_full()

    response = requests.put(url, json=body)
    assert response.status_code == 200

    token_networks[0].update_balance.assert_called_once()
    call_args = token_networks[0].update_balance.call_args[0]

    channel_identifier: ChannelIdentifier = call_args[0]
    signer: Address = call_args[1]
    nonce: int = call_args[2]
    transferred_amount: int = call_args[3]
    locked_amount: int = call_args[4]

    assert channel_identifier == 123
    assert is_same_address(signer, private_key_to_address(private_keys[0]))
    assert nonce == 1
    assert transferred_amount == 1
    assert locked_amount == 0


def test_put_balance_sync_check(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address],
    private_keys: List[str],
):
    url = api_url + '/{}/12/balance'.format(token_network_addresses[0])

    token_networks[0].update_balance = mock.Mock(return_value=None)  # type: ignore

    balance_proof = BalanceProof(
        channel_identifier=123,
        token_network_address=token_network_addresses[0],
        nonce=1,
        chain_id=321,
        additional_hash="0x%064x" % 0,
        balance_hash="0x%064x" % 0,
    )
    balance_proof.signature = encode_hex(sign_data(private_keys[0], balance_proof.serialize_bin()))

    body = balance_proof.serialize_full()

    # path channel id and BP channel id are not equal
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith(
        'The channel id from the balance proof (123) and '
        'the request (12) do not match'
    )

    balance_proof = BalanceProof(
        channel_identifier=123,
        token_network_address=token_network_addresses[1],
        nonce=1,
        chain_id=321,
        additional_hash="0x%064x" % 0,
        balance_hash="0x%064x" % 0,
    )
    balance_proof.signature = encode_hex(sign_data(private_keys[0], balance_proof.serialize_bin()))

    body = balance_proof.serialize_full()

    # now the network address doesn't match
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('The token network address from the balance proof')


def test_put_balance_path_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    body: Dict = dict()

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

    body: Dict = dict()
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == "'message_type' is a required property"

    # here the balance_hash property is missing
    body = dict(
        message_type='BalanceProof',
        channel_identifier=123,
        token_network_address=token_network_addresses[1],
        nonce=1,
        chain_id=321,
        additional_hash="0x%064x" % 0,
    )
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == "'balance_hash' is a required property"


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

    token_networks[0].update_fee = mock.Mock(return_value=None)  # type: ignore

    fee_info = FeeInfo(
        token_network_address=token_network_addresses[0],
        channel_identifier=123,
        chain_id=1,
        nonce=1,
        percentage_fee=0.02
    )
    fee_info.signature = encode_hex(sign_data(private_keys[0], fee_info.serialize_bin()))

    body = fee_info.serialize_full()

    response = requests.put(url, json=body)
    assert response.status_code == 200
    token_networks[0].update_fee.assert_called_once()
    call_args = token_networks[0].update_fee.call_args[0]

    channel_id: int = call_args[0]
    sender: str = call_args[1]
    nonce: int = call_args[2]
    fee: float = call_args[3]

    assert channel_id == 123
    assert is_same_address(sender, private_key_to_address(private_keys[0]))
    assert nonce == 1
    assert fee == 0.02


def test_put_fee_sync_check(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address],
    private_keys: List[str],
):
    url = api_url + '/{}/12/fee'.format(token_network_addresses[0])

    token_networks[0].update_fee = mock.Mock(return_value=None)  # type: ignore

    fee_info = FeeInfo(
        token_network_address=token_network_addresses[0],
        channel_identifier=123,
        chain_id=1,
        nonce=1,
        percentage_fee=0.02
    )
    fee_info.signature = encode_hex(sign_data(private_keys[0], fee_info.serialize_bin()))

    body = fee_info.serialize_full()

    # path channel id and FeeInfo id are not equal
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith(
        'The channel id from the fee info (123) and '
        'the request (12) do not match'
    )

    fee_info = FeeInfo(
        token_network_address=token_network_addresses[1],
        channel_identifier=123,
        chain_id=1,
        nonce=1,
        percentage_fee=0.02
    )
    fee_info.signature = encode_hex(sign_data(private_keys[0], fee_info.serialize_bin()))

    body = fee_info.serialize_full()

    # now the network address doesn't match
    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'].startswith('The token network address from the fee info')


def test_put_fee_path_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_network_addresses: List[Address]
):
    body: Dict = dict()

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


def test_put_fee_validation(
    api_sut: ServiceApi,
    api_url: str,
    token_networks: List[TokenNetwork],
    token_network_addresses: List[Address],
    private_keys: List[str],
):
    url = api_url + '/{}/123/fee'.format(token_network_addresses[0])

    token_networks[0].update_fee = mock.Mock(return_value=None)  # type: ignore

    fee_info = FeeInfo(
        token_network_address=token_network_addresses[0],
        channel_identifier=123,
        chain_id=1,
        nonce=1,
        percentage_fee=0.02
    )
    fee_info.signature = encode_hex(sign_data(private_keys[0], fee_info.serialize_bin()))

    body = fee_info.serialize_data()
    body['message_type'] = 'FeeInfo'

    # remove the fee to make it an invalid message
    del body['percentage_fee']

    response = requests.put(url, json=body)
    assert response.status_code == 400
    assert response.json()['error'] == "'percentage_fee' is a required property"


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
        {
            'path': [addresses[0], addresses[1], addresses[2]],
            'estimated_fee': 0.0018
        },
        {
            'path': [addresses[0], addresses[1], addresses[4], addresses[3], addresses[2]],
            'estimated_fee': 0.0131
        }
    ]

    # there is no connection between 0 and 5, this should return an error
    url = base_url + '?from={}&to={}&value=10&num_paths=3'.format(
        addresses[0],
        addresses[5]
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'].startswith('No suitable path found for transfer from')
