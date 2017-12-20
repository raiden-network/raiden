# -*- coding: utf-8 -*-
from binascii import hexlify
import os
import string
from itertools import chain, product

import pytest
from ethereum.abi import ValueOutOfBounds
from ethereum.tools import _solidity, tester
from ethereum.tools.tester import TransactionFailed
from ethereum.utils import normalize_address

from raiden.constants import INT64_MIN, INT64_MAX, UINT64_MIN, UINT64_MAX
from raiden.messages import DirectTransfer
from raiden.tests.utils.factories import make_privkey_address
from raiden.tests.utils.tests import get_relative_contract
from raiden.transfer.state import MerkleTreeState
from raiden.transfer.merkle_tree import (
    compute_layers,
    merkleroot,
    compute_merkleproof_for,
)
from raiden.utils import get_project_root, sha3

# The computeMerkleRoot function only computes the proof regardless of what the
# hashes are encoding, so just use some arbitrary data to produce a merkle tree.
ARBITRARY_DATA = [
    letter.encode() * 32
    for letter in string.ascii_uppercase[:7]
]
FAKE_TREE = [
    ARBITRARY_DATA[:1],
    ARBITRARY_DATA[:2],
    ARBITRARY_DATA[:3],
    ARBITRARY_DATA[:7],
]

HASH = sha3(b'muchcodingsuchwow_______________')


def deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address):
    contracts_path = os.path.join(get_project_root(), 'smart_contracts')
    raiden_remap = 'raiden={}'.format(contracts_path)

    contract_libraries = {
        'NettingChannelLibrary': hexlify(tester_nettingchannel_library_address),
    }

    auxiliary_tester_compiled = _solidity.compile_contract(
        get_relative_contract(__file__, 'AuxiliaryTester.sol'),
        'AuxiliaryTester',
        contract_libraries,
        extra_args=raiden_remap
    )
    auxiliary_tester_address = tester_chain.contract(
        auxiliary_tester_compiled['bin'],
        language='evm',
        sender=tester.k0
    )
    auxiliary = tester.ABIContract(
        tester_chain,
        auxiliary_tester_compiled['abi'],
        auxiliary_tester_address
    )
    tester_chain.mine(number_of_blocks=1)

    return auxiliary


def test_min_uses_usigned(tester_chain, tester_nettingchannel_library_address):
    """ Min cannot be called with negative values. """
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    INVALID_VALUES = [INT64_MIN, -1]
    VALID_VALUES = [0, INT64_MAX, UINT64_MAX]

    all_invalid = chain(
        product(VALID_VALUES, INVALID_VALUES),
        product(INVALID_VALUES, VALID_VALUES),
    )

    for a, b in all_invalid:
        with pytest.raises(ValueOutOfBounds):
            auxiliary.min(a, b)


def test_max_uses_unsigned(tester_chain, tester_nettingchannel_library_address):
    """ Max cannot be called with negative values. """
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    INVALID_VALUES = [INT64_MIN, -1]
    VALID_VALUES = [0, INT64_MAX, UINT64_MAX]

    all_invalid = chain(
        product(VALID_VALUES, INVALID_VALUES),
        product(INVALID_VALUES, VALID_VALUES),
    )

    for a, b in all_invalid:
        with pytest.raises(ValueOutOfBounds):
            auxiliary.max(a, b)


def test_min(tester_chain, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    VALUES = [UINT64_MIN, 1, INT64_MAX, UINT64_MAX]
    for a, b in product(VALUES, VALUES):
        assert auxiliary.min(a, b) == min(a, b)


def test_max(tester_chain, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    VALUES = [UINT64_MIN, 1, INT64_MAX, UINT64_MAX]
    for a, b in product(VALUES, VALUES):
        assert auxiliary.max(a, b) == max(a, b)


@pytest.mark.parametrize('tree', FAKE_TREE)
def test_merkle_proof(
        tree,
        tester_chain,
        tester_nettingchannel_library_address):
    """ computeMerkleRoot and the python implementation must compute the same value. """

    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    hashes = [sha3(element) for element in tree]
    layers = compute_layers(hashes)
    merkletree = MerkleTreeState(layers)

    for element in tree:
        proof = compute_merkleproof_for(merkletree, sha3(element))

        smart_contact_root = auxiliary.computeMerkleRoot(
            element,
            b''.join(proof),
        )

        assert smart_contact_root == merkleroot(merkletree)


@pytest.mark.parametrize('tree', FAKE_TREE)
def test_merkle_proof_missing_byte(
        tree,
        tester_chain,
        tester_nettingchannel_library_address):
    """ computeMerkleRoot must fail if the proof is missing a byte. """

    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    hashes = [sha3(element) for element in tree]
    layers = compute_layers(hashes)
    merkletree = MerkleTreeState(layers)

    element = hashes[-1]
    proof = compute_merkleproof_for(merkletree, element)

    # for each element of the proof, remove a byte from the start and the end and test it
    for element_to_tamper in range(len(proof)):
        tampered_proof = list(proof)
        tampered_proof[element_to_tamper] = tampered_proof[element_to_tamper][:-1]

        with pytest.raises(TransactionFailed):
            auxiliary.computeMerkleRoot(
                element,
                b''.join(tampered_proof),
            )

        tampered_proof = list(proof)
        tampered_proof[element_to_tamper] = tampered_proof[element_to_tamper][1:]

        with pytest.raises(TransactionFailed):
            auxiliary.computeMerkleRoot(
                element,
                b''.join(tampered_proof),
            )


def test_signature_split(tester_chain, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)

    privkey, address = make_privkey_address()
    msg = DirectTransfer(
        identifier=1,
        nonce=1,
        token='x' * 20,
        channel=auxiliary.address,
        transferred_amount=10,
        recipient='y' * 20,
        locksroot=HASH
    )
    msg.sign(privkey, address)
    msg = msg.encode()
    # signature = len(msg) - 65
    signature = msg[len(msg) - 65:]

    signature = signature[:-1] + chr(27).encode()
    r, s, v = auxiliary.signatureSplit(signature)
    assert v == 27
    assert r == signature[:32]
    assert s == signature[32:64]

    signature = signature[:-1] + chr(28).encode()
    _, _, v = auxiliary.signatureSplit(signature)
    assert v == 28

    with pytest.raises(TransactionFailed):
        signature = signature[:-1] + chr(4).encode()
        r, s, v = auxiliary.signatureSplit(signature)


def test_recoverAddressFromSignature(tester_chain, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_chain, tester_nettingchannel_library_address)
    privkey, address = make_privkey_address()

    msg = DirectTransfer(
        identifier=1,
        nonce=1,
        token='x' * 20,
        channel=auxiliary.address,
        transferred_amount=10,
        recipient='y' * 20,
        locksroot=HASH
    )
    msg.sign(privkey, address)
    data = msg.encode()
    signature = data[-65:]
    extra_hash = sha3(data[:-65])

    computed_address = auxiliary.recoverAddressFromSignature(
        msg.nonce,
        msg.transferred_amount,
        msg.locksroot,
        extra_hash,
        signature
    )

    assert normalize_address(computed_address) == msg.sender
