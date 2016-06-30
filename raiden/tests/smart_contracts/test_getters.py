import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import TransactionFailed

from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3
from raiden.messages import Lock, DirectTransfer
from raiden.encoding.signing import recover_publickey, address_from_key, sign
from raiden.network.rpc.client import get_contract_path

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

decode_lib = get_contract_path('Decoder.sol')
getter_path = get_contract_path('Getters.sol')


# @pytest.mark.xfail
def test_ncc():

    token_library_path = get_contract_path('StandardToken.sol')
    token_path = get_contract_path('HumanStandardToken.sol')

    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    # Token creation
    lib_token = s.abi_contract(None, path=token_library_path, language="solidity")
    token = s.abi_contract(None, path=token_path, language="solidity", libraries={'StandardToken': lib_token.address.encode('hex')}, constructor_parameters=[10000, "raiden", 0, "rd"])
    # Getter creation
    lib_getter = s.abi_contract(None, path=decode_lib, language="solidity")
    getter = s.abi_contract(None, path=getter_path, language="solidity", libraries={'Decoder': lib_getter.address.encode('hex')})

    INITIATOR_PRIVKEY = tester.k0
    INITIATOR_ADDRESS = privtoaddr(INITIATOR_PRIVKEY)

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
    balance = 1
    recipient = RECIPIENT_ADDRESS
    locksroot = LOCKSROOT

    msg = DirectTransfer(
        nonce,
        asset,
        balance,
        recipient,
        locksroot,
    )
    msg.sign(INITIATOR_PRIVKEY)
    packed = msg.packed()
    direct_transfer = str(packed.data)

    # pure python recover
    sen = recover_publickey(direct_transfer[:148], str(packed.signature))
    assert address_from_key(sen) == tester.a0

    # addr = getter.ecTest(direct_transfer[:148], sig)
    # assert addr == INITIATOR_ADDRESS.encode('hex')
    sender = getter.getSender(direct_transfer)
    assert sender == tester.a0.encode('hex')

    # with sigSplit directly in Getters.sol
    r, s, v = getter.sigSplit(str(packed.signature))
    assert r == str(packed.signature[:32])
    assert s == str(packed.signature[32:64])
    assert v == packed.signature[64] + 27

    sender = getter.getSender(direct_transfer)
    assert sender == tester.a0.encode('hex')
