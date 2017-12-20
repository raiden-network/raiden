# -*- coding: utf-8 -*-
from binascii import hexlify
import os

import ethereum.abi
from ethereum.tools import tester, _solidity

from raiden.utils import get_contract_path


def test_token():
    standard_token_path = get_contract_path('StandardToken.sol')
    human_token_path = get_contract_path('HumanStandardToken.sol')

    test_chain = tester.Chain()

    address0 = tester.a0
    address1 = tester.a1

    standard_token_compiled = _solidity.compile_contract(
        standard_token_path,
        "StandardToken"
    )
    standard_token_address = test_chain.contract(
        standard_token_compiled['bin'],
        language='evm',
        sender=tester.k0
    )
    contract_libraries = {
        'StandardToken': hexlify(standard_token_address),
    }

    human_token_compiled = _solidity.compile_contract(
        human_token_path,
        'HumanStandardToken',
        contract_libraries
    )
    ct = ethereum.abi.ContractTranslator(human_token_compiled['abi'])
    human_token_args = ct.encode_constructor_arguments([10000, 'raiden', 0, 'rd'])
    human_token_address = test_chain.contract(
        human_token_compiled['bin'] + human_token_args,
        language='evm',
        sender=tester.k0
    )
    human_token = tester.ABIContract(test_chain, human_token_compiled['abi'], human_token_address)
    test_chain.mine()

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

    test_chain = tester.Chain()

    address0 = tester.a0
    address1 = tester.a1

    standard_token_compiled = _solidity.compile_contract(
        standard_token_path,
        "StandardToken"
    )
    standard_token_address = test_chain.contract(
        standard_token_compiled['bin'],
        language='evm',
        sender=tester.k0
    )
    contract_libraries = {
        'StandardToken': hexlify(standard_token_address),
    }

    human_token_compiled = _solidity.compile_contract(
        human_token_path,
        'HumanStandardToken',
        contract_libraries
    )
    ct = ethereum.abi.ContractTranslator(human_token_compiled['abi'])
    human_token_args = ct.encode_constructor_arguments([10000, 'raiden', 0, 'rd'])
    human_token_address = test_chain.contract(
        human_token_compiled['bin'] + human_token_args,
        language='evm',
        sender=tester.k0
    )
    human_token = tester.ABIContract(test_chain, human_token_compiled['abi'], human_token_address)

    test_token_compiled = _solidity.compile_contract(
        test_path,
        'SimpleApproveTransfer',
        contract_libraries
    )
    ct = ethereum.abi.ContractTranslator(test_token_compiled['abi'])
    test_token_args = ct.encode_constructor_arguments([human_token_address])
    test_token_address = test_chain.contract(
        test_token_compiled['bin'] + test_token_args,
        language='evm',
        sender=tester.k0
    )
    test = tester.ABIContract(test_chain, test_token_compiled['abi'], test_token_address)

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
