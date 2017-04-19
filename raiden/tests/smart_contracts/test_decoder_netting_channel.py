# -*- coding: utf-8 -*-
import os

import pytest
from ethereum import tester
from secp256k1 import PrivateKey
from pyethapp.jsonrpc import address_decoder

from raiden.encoding.signing import GLOBAL_CTX
from raiden.tests.utils.tests import get_test_contract_path
from raiden.utils import sha3, privatekey_to_address, get_project_root
from raiden.tests.utils.messages import (
    make_direct_transfer,
    make_mediated_transfer,
    make_refund_transfer,
)


VALID_LOCKSROOT = [
    sha3('WaldemarstrWaldemarstrWaldemarst'),
    sha3('SikorkaSikorkaSikorkaSikorkaSiko'),
    sha3('MainzMainzMainzMainzMainzMainzMa'),
]


def assert_decoder_results(message, decoder):
    message_encoded = message.encode()
    transfer_raw, signing_address = decoder.getTransferRawAddress(message_encoded)

    assert address_decoder(signing_address) == message.sender
    assert transfer_raw == message_encoded[:-65]

    (
        nonce_decoded,
        locksroot_decoded,
        transferred_amount_decoded
    ) = decoder.decodeTransfer(transfer_raw, sender=tester.DEFAULT_KEY)

    assert message.nonce == nonce_decoded
    assert message.transferred_amount == transferred_amount_decoded
    assert message.locksroot == locksroot_decoded


def deploy_decoder_tester(tester_state, tester_nettingchannel_library_address):
    contracts_path = os.path.join(get_project_root(), 'smart_contracts')
    raiden_remap = 'raiden={}'.format(contracts_path)

    decoder = tester_state.abi_contract(
        None,
        path=get_test_contract_path('DecoderTester.sol'),
        language='solidity',
        libraries={'NettingChannelLibrary': tester_nettingchannel_library_address.encode('hex')},
        extra_args=raiden_remap,
    )
    tester_state.mine(number_of_blocks=1)

    return decoder


@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('locksroot', VALID_LOCKSROOT)
def test_decode_direct_transfer(
        identifier,
        nonce,
        transferred_amount,
        locksroot,
        tester_state,
        tester_nettingchannel_library_address):

    privatekey0 = tester.DEFAULT_KEY
    address0 = privatekey_to_address(privatekey0)

    decoder = deploy_decoder_tester(tester_state, tester_nettingchannel_library_address)

    direct_transfer = make_direct_transfer(
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locksroot=locksroot,
    )
    direct_transfer.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)

    assert_decoder_results(direct_transfer, decoder)


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('fee', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('locksroot', VALID_LOCKSROOT)
def test_decode_mediated_transfer(
        amount,
        identifier,
        nonce,
        transferred_amount,
        locksroot,
        fee,
        tester_state,
        tester_nettingchannel_library_address):

    privatekey0 = tester.DEFAULT_KEY
    address0 = privatekey_to_address(privatekey0)

    decoder = deploy_decoder_tester(tester_state, tester_nettingchannel_library_address)

    mediated_transfer = make_mediated_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        fee=fee,
        transferred_amount=transferred_amount,
        locksroot=locksroot,
    )

    mediated_transfer.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)

    assert_decoder_results(mediated_transfer, decoder)


@pytest.mark.parametrize('amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('identifier', [0, 2 ** 64 - 1])
@pytest.mark.parametrize('nonce', [1, 2 ** 64 - 1])
@pytest.mark.parametrize('transferred_amount', [0, 2 ** 256 - 1])
@pytest.mark.parametrize('locksroot', VALID_LOCKSROOT)
def test_decode_refund_transfer(
        amount,
        identifier,
        nonce,
        transferred_amount,
        locksroot,
        tester_state,
        tester_nettingchannel_library_address):

    privatekey0 = tester.DEFAULT_KEY
    address0 = privatekey_to_address(privatekey0)

    decoder = deploy_decoder_tester(tester_state, tester_nettingchannel_library_address)

    refund_transfer = make_refund_transfer(
        amount=amount,
        identifier=identifier,
        nonce=nonce,
        transferred_amount=transferred_amount,
        locksroot=locksroot,
    )
    refund_transfer.sign(PrivateKey(privatekey0, ctx=GLOBAL_CTX, raw=True), address0)

    assert_decoder_results(refund_transfer, decoder)
