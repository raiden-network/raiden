from unittest.mock import patch

import pytest
from eth_utils import encode_hex

from raiden.exceptions import ServiceRequestFailed
from raiden.network.pathfinding import get_pfs_iou, make_iou, update_iou
from raiden.utils import privatekey_to_address
from raiden.utils.typing import Address, TokenNetworkAddress
from raiden_contracts.utils.proofs import sign_one_to_n_iou


@pytest.mark.skip(reason="TODO: vulnerable to evil PFS")
def test_get_pfs_iou():
    token_network_address = TokenNetworkAddress(bytes([1] * 20))
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))
    with patch('raiden.network.pathfinding.requests.get') as get_mock:
        # No previous IOU
        get_mock.return_value.json.return_value = {'last_iou': None}
        assert get_pfs_iou('http://example.com', token_network_address) is None

        # Previous IOU
        iou = {
            'sender': encode_hex(sender),
            'receiver': encode_hex(receiver),
            'amount': 10,
            'expiration_block': 1000,
        }
        iou['signature'] = sign_one_to_n_iou(
            privatekey=encode_hex(privkey),
            sender=iou['sender'],
            receiver=iou['receiver'],
            amount=iou['amount'],
            expiration=iou['expiration_block'],
        )
        get_mock.return_value.json.return_value = {'last_iou': iou}
        assert get_pfs_iou('http://example.com', token_network_address) == iou

        # Previous IOU with increased amount by evil PFS
        with pytest.raises(ServiceRequestFailed):
            iou['amount'] += 10
            get_pfs_iou('http://example.com', token_network_address)


@pytest.mark.skip(
    reason="TODO: make_iou is declared to take sender as bytes, but actually expects hex",
)
def test_make_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))
    config = {
        'pathfinding_eth_address': encode_hex(receiver),
        'pathfinding_iou_timeout': 10000,
        'pathfinding_max_fee': 100,
    }

    make_iou(config, our_address=sender, privkey=privkey, block_number=10)


def test_update_iou():
    privkey = bytes([2] * 32)
    sender = Address(privatekey_to_address(privkey))
    receiver = Address(bytes([1] * 20))

    # prepate iou
    iou = {
        'sender': encode_hex(sender),
        'receiver': encode_hex(receiver),
        'amount': 10,
        'expiration_block': 1000,
    }
    iou['signature'] = sign_one_to_n_iou(
        privatekey=encode_hex(privkey),
        sender=iou['sender'],
        receiver=iou['receiver'],
        amount=iou['amount'],
        expiration=iou['expiration_block'],
    )

    # update and compare
    added_amount = 10
    new_iou = update_iou(iou=iou.copy(), privkey=privkey, added_amount=added_amount)
    assert new_iou['amount'] == iou['amount'] + added_amount
    assert new_iou['sender'] == iou['sender']
    assert new_iou['receiver'] == iou['receiver']
    assert new_iou['signature'] != iou['signature']
