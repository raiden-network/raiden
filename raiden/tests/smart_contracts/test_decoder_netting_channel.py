# -*- coding: utf-8 -*-
import os

from secp256k1 import PrivateKey
from ethereum import tester
from raiden.utils import sha3, privatekey_to_address, get_project_root
from raiden.messages import DirectTransfer, Lock, MediatedTransfer, RefundTransfer
from raiden.encoding.messages import wrap_and_validate
from raiden.encoding.signing import GLOBAL_CTX, address_from_key
from raiden.tests.utils.tests import get_test_contract_path


def deploy_decoder_tester(tester_state, token_address, address1, address2, settle_timeout):
    netting_chnanel_library_path = os.path.join(
        get_project_root(),
        'smart_contracts',
        'NettingChannelLibrary.sol',
    )

    nettingchannel_lib = tester_state.abi_contract(
        None,
        path=netting_chnanel_library_path,
        language='solidity'
    )
    tester_state.mine(number_of_blocks=1)
    decode_tester = tester_state.abi_contract(
        None,
        path=get_test_contract_path('DecoderTester.sol'),
        language='solidity',
        libraries={
            'NettingChannelLibrary': nettingchannel_lib.address.encode('hex')
        },
        constructor_parameters=(
            token_address,
            address1,
            address2,
            settle_timeout
        ),
        extra_args='raiden={}'.format(os.path.join(get_project_root(), 'smart_contracts'))
    )
    tester_state.mine(number_of_blocks=1)

    return decode_tester


def test_decode_direct_transfer(settle_timeout, tester_state, tester_token):
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)

    dtester = deploy_decoder_tester(
        tester_state,
        tester_token.address,
        address0,
        address1,
        settle_timeout
    )

    locksroot = sha3('Waldemarstr')

    message = DirectTransfer(
        identifier=1,
        nonce=2,
        token=tester_token.address,
        transferred_amount=1337,
        recipient=address1,
        locksroot=locksroot
    )

    message.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)
    _, publickey = wrap_and_validate(message.encode())
    recovered_address = address_from_key(publickey)
    assert recovered_address == address0

    assert dtester.testDecodeTransfer(message.encode(), sender=privatekey1) is True
    assert dtester.decodedNonce() == 2
    assert dtester.decodedToken() == tester_token.address.encode('hex')
    assert dtester.decodedLocksroot() == locksroot


def test_decode_mediated_transfer(settle_timeout, tester_state, tester_token):
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    privatekey2 = tester.k2
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)
    address2 = privatekey_to_address(privatekey2)

    dtester = deploy_decoder_tester(
        tester_state,
        tester_token.address,
        address0,
        address1,
        settle_timeout
    )

    locksroot = sha3('Sikorka')
    amount = 1337
    expiration = 5
    lock = Lock(amount, expiration, locksroot)

    message = MediatedTransfer(
        identifier=313151,
        nonce=88924902,
        token=tester_token.address,
        transferred_amount=amount,
        recipient=address1,
        locksroot=locksroot,
        lock=lock,
        target=address2,
        initiator=address0
    )

    message.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)
    _, publickey = wrap_and_validate(message.encode())
    recovered_address = address_from_key(publickey)
    assert recovered_address == address0

    assert dtester.testDecodeTransfer(message.encode(), sender=privatekey1) is True
    assert dtester.decodedNonce() == 88924902
    assert dtester.decodedToken() == tester_token.address.encode('hex')
    assert dtester.decodedLocksroot() == locksroot


def test_decode_refund_transfer(settle_timeout, tester_state, tester_token):
    privatekey0 = tester.DEFAULT_KEY
    privatekey1 = tester.k1
    address0 = privatekey_to_address(privatekey0)
    address1 = privatekey_to_address(privatekey1)

    dtester = deploy_decoder_tester(
        tester_state,
        tester_token.address,
        address0,
        address1,
        settle_timeout
    )

    locksroot = sha3('Mainz')
    amount = 1337
    expiration = 19
    lock = Lock(amount, expiration, locksroot)

    message = RefundTransfer(
        identifier=321313,
        nonce=4242452,
        token=tester_token.address,
        transferred_amount=amount,
        recipient=address1,
        locksroot=locksroot,
        lock=lock
    )

    message.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)
    _, publickey = wrap_and_validate(message.encode())
    recovered_address = address_from_key(publickey)
    assert recovered_address == address0

    assert dtester.testDecodeTransfer(message.encode(), sender=privatekey1) is True
    assert dtester.decodedNonce() == 4242452
    assert dtester.decodedToken() == tester_token.address.encode('hex')
    assert dtester.decodedLocksroot() == locksroot
