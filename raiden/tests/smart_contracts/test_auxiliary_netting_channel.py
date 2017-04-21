# -*- coding: utf-8 -*-
import os
from itertools import chain, product

import pytest
from ethereum.abi import ValueOutOfBounds

from raiden.constants import INT64_MIN, INT64_MAX, UINT64_MIN, UINT64_MAX
from raiden.utils import get_project_root
from raiden.tests.utils.tests import get_test_contract_path


def deploy_auxiliary_tester(tester_state, tester_nettingchannel_library_address):
    contracts_path = os.path.join(get_project_root(), 'smart_contracts')
    raiden_remap = 'raiden={}'.format(contracts_path)

    auxiliary = tester_state.abi_contract(
        None,
        path=get_test_contract_path('AuxiliaryTester.sol'),
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
