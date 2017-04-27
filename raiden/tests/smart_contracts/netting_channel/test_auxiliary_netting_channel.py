# -*- coding: utf-8 -*-
import os
import string
from itertools import chain, product

import pytest
from ethereum.abi import ValueOutOfBounds
from ethereum.tester import TransactionFailed

from raiden.constants import INT64_MIN, INT64_MAX, UINT64_MIN, UINT64_MAX
from raiden.utils import get_project_root, sha3
from raiden.mtree import Merkletree
from raiden.tests.utils.tests import get_relative_contract

# The computeMerkleRoot function only computes the proof regardless of what the
# hashes are encoding, so just use some arbitrary data to produce a merkle tree.
ARBITRARY_DATA = [
    letter * 32
    for letter in string.ascii_uppercase[:7]
]
FAKE_TREE = [
    ARBITRARY_DATA[:1],
    ARBITRARY_DATA[:2],
    ARBITRARY_DATA[:3],
    ARBITRARY_DATA[:7],
]


def deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address):
    contracts_path = os.path.join(get_project_root(), 'smart_contracts')
    raiden_remap = 'raiden={}'.format(contracts_path)

    auxiliary = tester_state.abi_contract(
        None,
        path=get_relative_contract(__file__, 'AuxiliaryTester.sol'),
        language='solidity',
        libraries={'NettingChannelLibrary': tester_nettingchannel_library_address.encode('hex')},
        extra_args=raiden_remap,
    )
    tester_state.mine(number_of_blocks=1)

    return auxiliary


def test_min_uses_usigned(tester_state, tester_nettingchannel_library_address):
    """ Min cannot be called with negative values. """
    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    INVALID_VALUES = [INT64_MIN, -1]
    VALID_VALUES = [0, INT64_MAX, UINT64_MAX]

    all_invalid = chain(
        product(VALID_VALUES, INVALID_VALUES),
        product(INVALID_VALUES, VALID_VALUES),
    )

    for a, b in all_invalid:
        with pytest.raises(ValueOutOfBounds):
            auxiliary.min(a, b)


def test_max_uses_unsigned(tester_state, tester_nettingchannel_library_address):
    """ Max cannot be called with negative values. """
    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    INVALID_VALUES = [INT64_MIN, -1]
    VALID_VALUES = [0, INT64_MAX, UINT64_MAX]

    all_invalid = chain(
        product(VALID_VALUES, INVALID_VALUES),
        product(INVALID_VALUES, VALID_VALUES),
    )

    for a, b in all_invalid:
        with pytest.raises(ValueOutOfBounds):
            auxiliary.max(a, b)


def test_min(tester_state, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    VALUES = [UINT64_MIN, 1, INT64_MAX, UINT64_MAX]
    for a, b in product(VALUES, VALUES):
        assert auxiliary.min(a, b) == min(a, b)


def test_max(tester_state, tester_nettingchannel_library_address):
    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    VALUES = [UINT64_MIN, 1, INT64_MAX, UINT64_MAX]
    for a, b in product(VALUES, VALUES):
        assert auxiliary.max(a, b) == max(a, b)


@pytest.mark.parametrize('tree', FAKE_TREE)
def test_merkle_proof(
        tree,
        tester_state,
        tester_nettingchannel_library_address):
    """ computeMerkleRoot and the python implementation must compute the same value. """

    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    hashes = [sha3(element) for element in tree]
    merkle_tree = Merkletree(hashes)

    for element in tree:
        proof = merkle_tree.make_proof(sha3(element))

        smart_contact_root = auxiliary.computeMerkleRoot(
            element,
            ''.join(proof),
        )

        assert smart_contact_root == merkle_tree.merkleroot


@pytest.mark.parametrize('tree', FAKE_TREE)
def test_merkle_proof_missing_byte(
        tree,
        tester_state,
        tester_nettingchannel_library_address):
    """ computeMerkleRoot must fail if the proof is missing a byte. """

    auxiliary = deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address)

    hashes = [sha3(element) for element in tree]
    merkle_tree = Merkletree(hashes)

    element = hashes[-1]
    merkle_proof = merkle_tree.make_proof(element)

    # for each element of the proof, remove a byte from the start and the end and test it
    for element_to_tamper in range(len(merkle_proof)):
        tampered_proof = list(merkle_proof)
        tampered_proof[element_to_tamper] = tampered_proof[element_to_tamper][:-1]

        with pytest.raises(TransactionFailed):
            auxiliary.computeMerkleRoot(
                element,
                ''.join(tampered_proof),
            )

        tampered_proof = list(merkle_proof)
        tampered_proof[element_to_tamper] = tampered_proof[element_to_tamper][1:]

        with pytest.raises(TransactionFailed):
            auxiliary.computeMerkleRoot(
                element,
                ''.join(tampered_proof),
            )
