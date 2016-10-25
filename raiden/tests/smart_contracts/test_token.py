# -*- coding: utf-8 -*-
import os

from ethereum import tester

from raiden.utils import get_contract_path


def test_token():
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    state = tester.state()
    state.block.number = 1158001

    address0 = tester.a0
    address1 = tester.a1

    standard_token = state.abi_contract(
        None,
        path=standard_token_path,
        language='solidity',
    )

    contract_libraries = {
        'StandardToken': standard_token.address.encode('hex'),
    }
    human_token = state.abi_contract(
        None,
        path=human_token_path,
        language='solidity',
        libraries=contract_libraries,
        constructor_parameters=[10000, 'raiden', 0, 'rd'],
    )

    # pylint: disable=no-member
    assert human_token.balanceOf(address0) == 10000
    assert human_token.balanceOf(address1) == 0
    assert human_token.transfer(address1, 5000) is True
    assert human_token.balanceOf(address0) == 5000
    assert human_token.balanceOf(address1) == 5000


def test_token_approve():
    test_path = os.path.join(os.path.dirname(__file__), 'SimpleApproveTransfer.sol')

    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    state = tester.state()
    state.block.number = 1158001

    address0 = tester.a0
    address1 = tester.a1

    standard_token = state.abi_contract(
        None,
        path=standard_token_path,
        language='solidity',
    )

    contract_libraries = {
        'StandardToken': standard_token.address.encode('hex'),
    }
    human_token = state.abi_contract(
        None,
        path=human_token_path,
        language='solidity',
        libraries=contract_libraries,
        constructor_parameters=[10000, 'raiden', 0, 'rd'],
    )

    test = state.abi_contract(
        None,
        path=test_path,
        language='solidity',
        constructor_parameters=[human_token.address],
    )

    # pylint: disable=no-member
    assert human_token.balanceOf(address0) == 10000
    assert human_token.balanceOf(address1) == 0
    assert human_token.balanceOf(test.address) == 0
    assert human_token.allowance(address0, address0) == 0
    assert human_token.allowance(address0, address1) == 0
    assert human_token.allowance(address0, test.address) == 0

    assert human_token.approve(test.address, 5000) is True
    assert human_token.balanceOf(address0) == 10000
    assert human_token.balanceOf(address1) == 0
    assert human_token.balanceOf(test.address) == 0
    assert human_token.allowance(address0, address0) == 0
    assert human_token.allowance(address0, address1) == 0
    assert human_token.allowance(address0, test.address) == 5000

    assert test.transfer(address1, 2000) is True
    assert human_token.balanceOf(address0) == 10000 - 2000
    assert human_token.balanceOf(address1) == 0 + 2000
    assert human_token.balanceOf(test.address) == 0
    assert human_token.allowance(address0, address0) == 0
    assert human_token.allowance(address0, address1) == 0
    assert human_token.allowance(address0, test.address) == 5000 - 2000
