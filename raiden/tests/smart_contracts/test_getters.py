import pytest

from ethereum import tester
from ethereum import slogging
from ethereum.tester import TransactionFailed

from raiden.mtree import merkleroot
from raiden.utils import privtoaddr, sha3
from raiden.messages import Lock, CancelTransfer, DirectTransfer, MediatedTransfer, Secret
from raiden.network.rpc.client import get_contract_path

log = slogging.getLogger(__name__)  # pylint: disable=invalid-name

INITIATOR_PRIVKEY = 'x' * 32
INITIATOR_ADDRESS = privtoaddr(INITIATOR_PRIVKEY)
SECRET = 'secret'

RECIPIENT_PRIVKEY = 'y' * 32
RECIPIENT_ADDRESS = privtoaddr(RECIPIENT_PRIVKEY)

TARGET_PRIVKEY = 'z' * 32
TARGET_ADDRESS = privtoaddr(TARGET_PRIVKEY)

ASSET_ADDRESS = sha3('asset')[:20]

HASHLOCK = sha3(INITIATOR_PRIVKEY)
LOCK_AMOUNT = 29
LOCK_EXPIRATION = 31
LOCK = Lock(LOCK_AMOUNT, LOCK_EXPIRATION, HASHLOCK)
LOCKSROOT = merkleroot([
    sha3(LOCK.as_bytes), ])   # print direct_transfer.encode('hex')


def test_ncc():
    decode_lib = get_contract_path('Decoder.sol')
    getter_path = get_contract_path('Getters.sol')

    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    # Token creation
    lib_getter = s.abi_contract(None, path=decode_lib, language="solidity")
    getter = s.abi_contract(None, path=getter_path, language="solidity", libraries={'Decoder': lib_getter.address.encode('hex')})

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
    ).sign(INITIATOR_PRIVKEY)
    packed = msg.packed()
    direct_transfer = str(packed.data)

    sender = getter.getSender(direct_transfer)
    assert sender == INITIATOR_ADDRESS
