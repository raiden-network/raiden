# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import TransactionFailed
from raiden.messages import Lock, DirectTransfer
from raiden.encoding.signing import recover_publickey, address_from_key, sign
from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3
from raiden.network.rpc.client import get_contract_path

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

token_library_path = get_contract_path('StandardToken.sol')
token_path = get_contract_path('HumanStandardToken.sol')
ncc_path = get_contract_path('NettingChannelContract.sol')

def test_ncc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000

    # Token creation
    lib_token = s.abi_contract(None, path=token_library_path, language="solidity")
    token = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_token.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])

    s.mine()

    c = s.abi_contract(None, path=ncc_path, language="solidity", constructor_parameters=[token.address, tester.a0, tester.a1, 30])

    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) == True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert c.settleTimeout() == 30
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

    INITIATOR_PRIVKEY = tester.k0

    RECIPIENT_PRIVKEY = tester.k1
    RECIPIENT_ADDRESS = privtoaddr(RECIPIENT_PRIVKEY)

    ASSET_ADDRESS = token.address

    HASHLOCK = sha3(INITIATOR_PRIVKEY)
    LOCK_AMOUNT = 29
    LOCK_EXPIRATION = 31
    LOCK = Lock(LOCK_AMOUNT, LOCK_EXPIRATION, HASHLOCK)
    LOCKSROOT = merkleroot([
        sha3(LOCK.as_bytes), ])   # print direct_transfer.encode('hex')

    nonce = 1
    asset = ASSET_ADDRESS
    transfered_amount = 1
    recipient = RECIPIENT_ADDRESS
    locksroot = LOCKSROOT

    msg = DirectTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
    ).sign(INITIATOR_PRIVKEY)
    packed = msg.packed()
    direct_transfer = str(packed.data)

    c.closeSingleFunded(direct_transfer)

    assert c.closed() == s.block.number
    assert c.closingAddress() == tester.a0.encode('hex')
    assert c.participants(0)[10] == 1
    assert c.participants(0)[11] == token.address.encode('hex')
    assert c.participants(0)[9] == tester.a0.encode('hex')
    assert c.participants(0)[12] == tester.a1.encode('hex')
    assert c.participants(0)[3] == 1
    assert c.participants(0)[6] == LOCKSROOT
    assert c.participants(0)[7] == '\x00' * 32


def test_two_messages():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000

    # Token creation
    lib_token = s.abi_contract(None, path=token_library_path, language="solidity")
    token = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_token.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])

    s.mine()

    c = s.abi_contract(None, path=ncc_path, language="solidity", constructor_parameters=[token.address, tester.a0, tester.a1, 30])

    # test tokens and distribute tokens
    assert token.balanceOf(tester.a0) == 10000
    assert token.balanceOf(tester.a1) == 0
    assert token.transfer(tester.a1, 5000) == True
    assert token.balanceOf(tester.a0) == 5000
    assert token.balanceOf(tester.a1) == 5000

    # test global variables
    assert c.settleTimeout() == 30
    assert c.assetAddress() == token.address.encode('hex')
    assert c.opened() == 0
    assert c.closed() == 0
    assert c.settled() == 0

    HASHLOCK1 = sha3(tester.k0)
    LOCK_AMOUNT1 = 29
    LOCK_EXPIRATION1 = 31
    LOCK1 = Lock(LOCK_AMOUNT1, LOCK_EXPIRATION1, HASHLOCK1)
    LOCKSROOT1 = merkleroot([
        sha3(LOCK1.as_bytes), ])   # print direct_transfer.encode('hex')

    nonce = 1
    asset = token.address
    transfered_amount = 1
    recipient = tester.a1
    locksroot = LOCKSROOT1

    msg1 = DirectTransfer(
        nonce,
        asset,
        transfered_amount,
        recipient,
        locksroot,
    ).sign(tester.k0)
    packed = msg1.packed()
    direct_transfer1 = str(packed.data)

    HASHLOCK2 = sha3(tester.k1)
    LOCK_AMOUNT2 = 29
    LOCK_EXPIRATION2 = 31
    LOCK2 = Lock(LOCK_AMOUNT2, LOCK_EXPIRATION2, HASHLOCK2)
    LOCKSROOT2 = merkleroot([
        sha3(LOCK2.as_bytes), ])   # print direct_transfer.encode('hex')

    locksroot = LOCKSROOT2

    msg2 = DirectTransfer(
        2,  # nonce
        token.address,  # asset
        3,  # transfered_amount
        tester.a0,  # recipient
        locksroot,
    ).sign(tester.k1)
    packed = msg2.packed()
    direct_transfer2 = str(packed.data)

    c.closeBiFunded(direct_transfer1, direct_transfer2)

    # Test with message sender tester.a0
    assert c.closed() == s.block.number
    assert c.closingAddress() == tester.a0.encode('hex')
    assert c.participants(0)[10] == 1
    assert c.participants(0)[11] == token.address.encode('hex')
    assert c.participants(0)[9] == tester.a0.encode('hex')
    assert c.participants(0)[12] == tester.a1.encode('hex')
    assert c.participants(0)[3] == 1
    assert c.participants(0)[6] == LOCKSROOT1
    assert c.participants(0)[7] == '\x00' * 32

    # Test with message sender tester.a1
    assert c.closed() == s.block.number
    assert c.closingAddress() == tester.a0.encode('hex')
    assert c.participants(1)[10] == 2
    assert c.participants(1)[11] == token.address.encode('hex')
    assert c.participants(1)[9] == tester.a1.encode('hex')
    assert c.participants(1)[12] == tester.a0.encode('hex')
    assert c.participants(1)[3] == 3
    assert c.participants(1)[6] == LOCKSROOT2
    assert c.participants(1)[7] == '\x00' * 32
