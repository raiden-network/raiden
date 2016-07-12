# -*- coding: utf8 -*-
import pytest

from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed
from raiden.mtree import merkleroot
from raiden.messages import Lock, DirectTransfer

from raiden.blockchain.abi import get_contract_path

decoder_path = get_contract_path('Decoder.sol')

# with open(decoder_path) as decoder_file:
    # decode_code = decoder_file.read()

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


def test_decode_secret():
    encoded_data = "040000000000000000000000000000000000000000000000000000000000736563726574d37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d43501"
    # longer than expected input
    bad_encoded_data = "040000000000000000000000000000000000000000000000000000000000736563726574d37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d4350101"

    data = encoded_data.decode('hex')
    bad_data = bad_encoded_data.decode('hex')

    s = tester.state()
    c = s.abi_contract(None, path=decoder_path, language="solidity")
    assert data[0] == '\x04'  # make sure data has right cmdid
    o1 = c.decodeSecret(data)
    assert o1[0][26:32] == 'secret'
    assert o1[0].encode('hex') == '0000000000000000000000000000000000000000000000000000736563726574'
    signature = 'd37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d43501'
    assert o1[1].encode('hex') == signature[:64]
    assert o1[2].encode('hex') == signature[64:128]
    assert o1[3] == int(signature[129]) + 27
    assert len(data) == 101
    # length doesn't match
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data)
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data[0:100])


def test_decode_transfer():
    bad_encoded_data = '0500000000000000000000010bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd823110747000000000000000000000000000000000000000000000000000000000000000160d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df510000000000000000000000000000000000000000000000000000000000000000ff9636ccb66e73219fd166cd6ffbc9c6215f74ff31c1fd4131cf532b29ee096f65278c459253fba65bf019c723a68bb4a6153ea8378cd1b15d55825e1a291b6f0001'
    bad_data = bad_encoded_data.decode('hex')

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
    data = str(packed.data)

    s = tester.state()
    c = s.abi_contract(None, path=decoder_path, language="solidity")
    o1 = c.decodeTransfer1(data)
    o2 = c.decodeTransfer2(data)
    assert data[0] == '\x05'  # make sure data has right cmdid
    assert len(data) == 213
    cmd_id_pad = o1[0]
    assert cmd_id_pad == data[:4]
    nonce = o1[1]
    assert nonce == packed.nonce
    asset = o1[2]
    assert asset == str(packed.asset).encode('hex')
    recipient = o1[3]
    assert len(recipient) == 40
    assert recipient == str(packed.recipient).encode('hex')
    transfered_amount = o1[4]
    assert transfered_amount == packed.transfered_amount
    optionalLocksroot = o2[0]
    assert optionalLocksroot == str(packed.locksroot)
    optionalSecret = o2[1]
    assert optionalSecret == '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')
    signature = str(packed.signature)
    r = o2[2]
    s = o2[3]
    v = o2[4]
    assert r == signature[:32]
    assert s == signature[32:64]
    assert v == int(signature[64].encode('hex')) + 27
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data)


def test_decode_mediated_transfer():
    encoded_data = '070000000000000000000001000000000000001f0bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd8231107473e20ab25eb721dd4b691516238df14f0f5d3f7a3ea0c0d77f61162072c606eff3d4ee1368ef600e960d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df515601c4475f2f6aa73d6a70a56f9c756f24d211a914cc7aff3fb80d2d8741c8680000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000001d000000000000000000000000000000000000000000000000000000000000000079d1479c11af904096d7e179c4184b84fd5765f0a0ab1cf44578ef7a545e1b7157c73df9c3ee2797ee379eb05b1b239cea0eec47f9e03adc546a4c0ff7dcc3a601'

    data = encoded_data.decode('hex')
    s = tester.state()
    c = s.abi_contract(None, path=decoder_path, language="solidity")

    assert data[0] == '\x07'  # make sure data has right cmdid
    assert len(data) == 325
    o1 = c.decodeMediatedTransfer1(data)
    o2 = c.decodeMediatedTransfer2(data)
    nonce = o1[0]
    assert nonce == 1
    expiration = o1[1]
    assert expiration == int('000000000000001f', 16)
    asset = o1[2]
    assert len(asset) == 40
    assert asset == sha3('asset')[:20].encode('hex')
    recipient = o1[3]
    assert len(recipient) == 40
    assert recipient == privtoaddr('y' * 32).encode('hex')
    target = o1[4]
    assert len(target) == 40
    assert target == privtoaddr('z' * 32).encode('hex')
    initiator = o1[5]
    assert len(initiator) == 40
    assert initiator == privtoaddr('x' * 32).encode('hex')
    locksroot = o1[6]
    assert locksroot == '60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51'.decode('hex')
    hashlock = o2[0]
    assert hashlock == sha3('x' * 32)
    balance = o2[1]
    assert balance == 1
    amount = o2[2]
    assert amount == 29  # int('000000000000000000000000000000000000000000000000000000000000001d', 16)
    fee = o2[3]
    assert fee == 0
    signature = '79d1479c11af904096d7e179c4184b84fd5765f0a0ab1cf44578ef7a545e1b7157c73df9c3ee2797ee379eb05b1b239cea0eec47f9e03adc546a4c0ff7dcc3a601'.decode('hex')
    r = o2[4]
    s = o2[5]
    v = o2[6]
    assert r == signature[:32]
    assert s == signature[32:64]
    assert v == int(signature[64].encode('hex')) + 27


def test_decode_cancel_transfer():
    encoded_data = '080000000000000000000001000000000000001f0bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd82311074760d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df510000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000001d5601c4475f2f6aa73d6a70a56f9c756f24d211a914cc7aff3fb80d2d8741c868f4966fe93b467d28f15befd438b7aa0e7b8fbf5f00ce1abe0cc4a0ddf9bcc7c45c9863b784f474dee3c0682a5aa4c982712b98fcd60f5e5d94038008a97e251300'

    data = encoded_data.decode('hex')
    s = tester.state()
    c = s.abi_contract(None, path=decoder_path, language="solidity")

    assert data[0] == '\x08'  # make sure data has right cmdid
    assert len(data) == 253
    o1 = c.decodeCancelTransfer1(data)
    o2 = c.decodeCancelTransfer2(data)
    nonce = o1[0]
    assert nonce == 1
    expiration = o1[1]
    assert expiration == int('000000000000001f', 16)
    asset = o1[2]
    assert len(asset) == 40
    assert asset == sha3('asset')[:20].encode('hex')
    recipient = o1[3]
    assert len(recipient) == 40
    assert recipient == privtoaddr('y' * 32).encode('hex')
    locksroot = o2[0]
    assert locksroot == '60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51'.decode('hex')
    balance = o2[1]
    assert balance == 1
    amount = o2[2]
    assert amount == 29  # int('000000000000000000000000000000000000000000000000000000000000001d', 16)
    hashlock = o2[3]
    assert hashlock == sha3('x' * 32)
    signature = 'f4966fe93b467d28f15befd438b7aa0e7b8fbf5f00ce1abe0cc4a0ddf9bcc7c45c9863b784f474dee3c0682a5aa4c982712b98fcd60f5e5d94038008a97e251300'.decode('hex')
    r = o2[4]
    s = o2[5]
    v = o2[6]
    assert r == signature[:32]
    assert s == signature[32:64]
    assert v == int(signature[64].encode('hex')) + 27
