from ethereum import tester

from raiden.utils import privtoaddr, sha3
from raiden.mtree import merkleroot
from raiden.messages import Lock, DirectTransfer
from raiden.encoding.signing import recover_publickey, address_from_key, sign
from raiden.network.rpc.client import get_contract_path

ec_path = get_contract_path('EcTest.sol')


def test_ec():
    state = tester.state()
    assert state.block.number < 1150000
    state.block.number = 1158001
    assert state.block.number > 1150000
    ec = state.abi_contract(None, path=ec_path, language='solidity')

    INITIATOR_PRIVKEY = 'x' * 32
    INITIATOR_ADDRESS = privtoaddr(INITIATOR_PRIVKEY)

    RECIPIENT_PRIVKEY = 'y' * 32
    RECIPIENT_ADDRESS = privtoaddr(RECIPIENT_PRIVKEY)

    ASSET_ADDRESS = sha3('asset')[:20]

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
    ).sign(INITIATOR_PRIVKEY)
    packed = msg.packed()
    direct_transfer = str(packed.data)
    sig, pub = sign(direct_transfer[:148], INITIATOR_PRIVKEY)

    assert sig == str(packed.signature)

    # pure python recover
    sen = recover_publickey(direct_transfer[:148], str(packed.signature))
    assert address_from_key(sen) == INITIATOR_ADDRESS

    # solidity ecrecover
    sender = ec.ecst(direct_transfer[:148], str(packed.signature))
    assert sender == INITIATOR_ADDRESS.encode('hex')
    sender = ec.ecst(direct_transfer[:148], sig)
    assert sender == INITIATOR_ADDRESS.encode('hex')
