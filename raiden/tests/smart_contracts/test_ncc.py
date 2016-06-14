# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import TransactionFailed

from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3
from raiden.messages import Lock, CancelTransfer, DirectTransfer, MediatedTransfer, Secret
from raiden.network.rpc.client import get_contract_path

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

tester.gas_limit = 9575081L


def test_ncc():
    token_library_path = get_contract_path('StandardToken.sol')
    token_path = get_contract_path('HumanStandardToken.sol')

    library_path = get_contract_path('Decoder.sol')
    ncc_path = get_contract_path('NettingChannelContract.sol.old')

    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    # Token creation
    lib_token = s.abi_contract(None, path=token_library_path, language="solidity")
    token = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_token.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])

    s.mine()

    lib_c = s.abi_contract(None, path=library_path, language="solidity")
    s.mine()
    c = s.abi_contract(None, path=ncc_path, language="solidity", libraries={'Decoder': lib_c.address.encode('hex')}, constructor_parameters=[token.address, tester.a0, tester.a1, 30])

    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) == True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert c.lockedTime() == 30
    assert c.assetAddress() == token.address.encode('hex')
    assert c.opened() == 0
    assert c.closed() == 0
    assert c.settled() == 0

    # test participants variables changed when constructing
    assert c.participants(0)[0] == tester.a0.encode('hex')
    assert c.participants(1)[0] == tester.a1.encode('hex')

    # test atIndex()
    # private must be removed from the function in order to work
    # assert c.atIndex(sha3('address1')[:20]) == 0
    # assert c.atIndex(sha3('address2')[:20]) == 1

    # test deposit(uint)
    assert token.balanceOf(c.address) == 0
    assert token.approve(c.address, 30) == True # allow the contract do deposit
    assert c.participants(0)[1] == 0
    with pytest.raises(TransactionFailed):
        c.deposit(5001)
    c.deposit(30)
    assert c.participants(0)[1] == 30
    assert token.balanceOf(c.address) == 30
    assert token.balanceOf(tester.a0) == 4970
    assert c.opened() == s.block.number

    # test open()
    # private must be removed from the function in order to work
    # assert c.opened() == 0  # channel is not yet opened
    # c.open()
    # assert c.opened() > 0
    # assert c.opened() <= s.block.number

    # test partner(address)
    # private must be removed from the function in order to work
    # assert c.partner(sha3('address1')[:20]) == sha3('address2')[:20].encode('hex')
    # assert c.partner(sha3('address2')[:20]) == sha3('address1')[:20].encode('hex')

    # test addrAndDep()
    a1, d1, a2, d2 = c.addrAndDep()
    assert a1 == tester.a0.encode('hex')
    assert a2 == tester.a1.encode('hex')
    assert d1 == 30
    assert d2 == 0

    # test close(message)

    lock = Lock(30, 31, sha3(tester.a0))
    locksroot = merkleroot([sha3(lock.as_bytes)],)
    msg = DirectTransfer(1, token.address, 15, tester.a1, locksroot).sign(tester.k0)
    packed = msg.packed()
    direct_transfer = str(packed.data)
    print direct_transfer.encode('hex')

    # c.closeOneWay(direct_transfer)
