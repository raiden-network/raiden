# -*- coding: utf8 -*-
import pytest


from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed


decode_code = '''
    contract Decoder {
        
        function slice(bytes a, uint start, uint end) returns (bytes n) {
            if (a.length < end) throw;
            if (start < 0) throw;
            if (start > end) throw;
            n = new bytes(end-start);
            for ( uint i = start; i < end; i ++) { //python style slice
                n[i-start] = a[i];
            }
        }
        
        function decodeSecret(bytes m) returns (bytes32 secret, bytes signature) {
            if (m.length != 101) throw;
            secret = bytesToBytes32(slice(m, 4, 36), secret);
            signature = slice(m, 36, 101);
        }
        
        function decodeTransfer(bytes m) returns (uint8 nonce, address asset, address recipient,
                                                  uint balance, bytes32 optionalLocksroot,
                                                  bytes32 optionalSecret, bytes signature) 
        {
            if (m.length != 213) throw;
            nonce = bytesToIntEight(slice(m, 4, 12), nonce);
            uint160 ia;
            asset = bytesToAddress(slice(m, 12, 32), ia);
            uint160 ir;
            recipient = bytesToAddress(slice(m, 32, 52), ir);
            balance = bytesToInt(slice(m, 52, 84), balance);
            optionalLocksroot = bytesToBytes32(slice(m, 84, 116), optionalLocksroot);
            optionalSecret = bytesToBytes32(slice(m, 116, 148), optionalSecret);
            signature = slice(m, 148, 213);

        }
        
        function decodeLockedTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                         address asset, address recipient) 
        {
            if (m.length != 253) throw;
            nonce = bytesToIntEight(slice(m, 4, 12), nonce);
            expiration = bytesToIntEight(slice(m, 12, 20), expiration);
            uint160 ia;
            asset = bytesToAddress(slice(m, 20, 40), ia);
            uint160 ir;
            recipient = bytesToAddress(slice(m, 40, 60), ir);
            
        }
        
        function decodeLockedTransfer2(bytes m) returns 
                                        (bytes32 locksroot, uint balance, uint amount,
                                         bytes32 hashlock, bytes signature) 
        {

            locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
            balance = bytesToInt(slice(m, 92, 124), balance);
            amount = bytesToInt(slice(m, 124, 156), amount);
            hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
            signature = slice(m, 188, 253);
        }
        
        function decodeMediatedTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                           address asset, address recipient,
                                                           address target) 
        {
            if (m.length != 325) throw;
            nonce = bytesToIntEight(slice(m, 4, 12), nonce);
            expiration = bytesToIntEight(slice(m, 12, 20), expiration);
            uint160 ia;
            asset = bytesToAddress(slice(m, 20, 40), ia);
            uint160 ir;
            recipient = bytesToAddress(slice(m, 40, 60), ir);
            uint160 it;
            target = bytesToAddress(slice(m, 60, 80), it);
            
        }
        
        function decodeMediatedTransfer2(bytes m) returns 
                                        (address initiator, bytes32 locksroot, bytes32 hashlock, 
                                         uint balance, uint amount, uint fee, bytes signature) 
        {
            uint160 ii;
            initiator = bytesToAddress(slice(m, 80, 100), ii);
            locksroot = bytesToBytes32(slice(m, 100, 132), locksroot);
            hashlock = bytesToBytes32(slice(m, 132, 164), hashlock);
            balance = bytesToInt(slice(m, 164, 196), balance);
            amount = bytesToInt(slice(m, 196, 228), amount);
            fee = bytesToInt(slice(m, 228, 260), fee);
            signature = slice(m, 260, 325);
        }
        
        function decodeCancelTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                   address asset, address recipient) 
        {
            if (m.length != 253) throw;
            nonce = bytesToIntEight(slice(m, 4, 12), nonce);
            expiration = bytesToIntEight(slice(m, 12, 20), expiration);
            uint160 ia;
            asset = bytesToAddress(slice(m, 20, 40), ia);
            uint160 ir;
            recipient = bytesToAddress(slice(m, 40, 60), ir);
        }
        
        function decodeCancelTransfer2(bytes m) returns (bytes32 locksroot, uint balance, 
                                                         uint amount, bytes32 hashlock, bytes signature) 
        {
            locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
            balance = bytesToInt(slice(m, 92, 124), balance);
            amount = bytesToInt(slice(m, 124, 156), amount);
            hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
            signature = slice(m, 188, 253); 
        }
        
        /* HELPER FUNCTIONS */
        
        function bytesToIntEight(bytes b, uint8 i) returns (uint8 res) {
            assembly { i := mload(add(b, 0x8)) }
            res = i;
        }
        
        // helper function
        function bytesToInt(bytes b, uint i) returns (uint res) {
            assembly { i := mload(add(b, 0x20)) }
            res = i;
        }
        
        // helper function
        function bytesToAddress(bytes b, uint160 i) returns (address add) {
            assembly { i := mload(add(b, 0x14)) }
            uint160 a = uint160(i);
            add = address(i);
        }
        
        function bytesToBytes32(bytes b, bytes32 i) returns (bytes32 bts) {
            assembly { i := mload(add(b, 0x20)) }
            bts = i;
        }
    }
'''


def test_decode_secret():
    encoded_data = "040000000000000000000000000000000000000000000000000000000000736563726574d37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d43501"
    # longer than expected input
    bad_encoded_data = "040000000000000000000000000000000000000000000000000000000000736563726574d37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d4350101"

    data = encoded_data.decode('hex')
    bad_data = bad_encoded_data.decode('hex')

    s = tester.state()
    c = s.abi_contract(decode_code, language="solidity")
    assert data[0] == '\x04'  # make sure data has right cmdid
    o1 = c.decodeSecret(data)
    assert o1[0][26:32] == 'secret'
    assert o1[0].encode('hex') == '0000000000000000000000000000000000000000000000000000736563726574'
    assert o1[1].encode('hex') == 'd37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d43501'
    assert len(data) == 101
    # length doesn't match
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data)
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data[0:100])


def test_decode_transfer():
    encoded_data = '0500000000000000000000010bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd823110747000000000000000000000000000000000000000000000000000000000000000160d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df510000000000000000000000000000000000000000000000000000000000000000ff9636ccb66e73219fd166cd6ffbc9c6215f74ff31c1fd4131cf532b29ee096f65278c459253fba65bf019c723a68bb4a6153ea8378cd1b15d55825e1a291b6f00'
    bad_encoded_data = '0500000000000000000000010bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd823110747000000000000000000000000000000000000000000000000000000000000000160d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df510000000000000000000000000000000000000000000000000000000000000000ff9636ccb66e73219fd166cd6ffbc9c6215f74ff31c1fd4131cf532b29ee096f65278c459253fba65bf019c723a68bb4a6153ea8378cd1b15d55825e1a291b6f0001'
    data = encoded_data.decode('hex')
    bad_data = bad_encoded_data.decode('hex')
    s = tester.state()
    c = s.abi_contract(decode_code, language="solidity")
    o1 = c.decodeTransfer(data)
    assert data[0] == '\x05'  # make sure data has right cmdid
    assert len(data) == 213
    nonce = o1[0]
    assert nonce == 1
    asset = o1[1]
    assert asset == sha3('asset')[:20].encode('hex')
    recipient = o1[2]
    assert len(recipient) == 40
    assert recipient == privtoaddr('y' * 32).encode('hex')
    balance = o1[3]
    assert balance == 1
    optionalLocksroot = o1[4]
    assert optionalLocksroot == '60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51'.decode('hex')
    optionalSecret = o1[5]
    assert optionalSecret == '0000000000000000000000000000000000000000000000000000000000000000'.decode('hex')
    signature = o1[6]
    assert signature == 'ff9636ccb66e73219fd166cd6ffbc9c6215f74ff31c1fd4131cf532b29ee096f65278c459253fba65bf019c723a68bb4a6153ea8378cd1b15d55825e1a291b6f00'.decode('hex')
    with pytest.raises(TransactionFailed):
        c.decodeSecret(bad_data)


def test_decode_mediated_transfer():
    encoded_data = '070000000000000000000001000000000000001f0bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd8231107473e20ab25eb721dd4b691516238df14f0f5d3f7a3ea0c0d77f61162072c606eff3d4ee1368ef600e960d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df515601c4475f2f6aa73d6a70a56f9c756f24d211a914cc7aff3fb80d2d8741c8680000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000001d000000000000000000000000000000000000000000000000000000000000000079d1479c11af904096d7e179c4184b84fd5765f0a0ab1cf44578ef7a545e1b7157c73df9c3ee2797ee379eb05b1b239cea0eec47f9e03adc546a4c0ff7dcc3a601'

    data = encoded_data.decode('hex')
    s = tester.state()
    c = s.abi_contract(decode_code, language="solidity")

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
    initiator = o2[0]
    assert len(initiator) == 40
    assert initiator == privtoaddr('x' * 32).encode('hex')
    locksroot = o2[1]
    assert locksroot == '60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51'.decode('hex')
    hashlock = o2[2]
    assert hashlock == sha3('x' * 32)
    balance = o2[3]
    assert balance == 1
    amount = o2[4]
    assert amount == 29  #int('000000000000000000000000000000000000000000000000000000000000001d', 16)
    fee = o2[5]
    assert fee == 0
    signature = o2[6]
    assert signature == '79d1479c11af904096d7e179c4184b84fd5765f0a0ab1cf44578ef7a545e1b7157c73df9c3ee2797ee379eb05b1b239cea0eec47f9e03adc546a4c0ff7dcc3a601'.decode('hex')


def test_decode_cancel_transfer():
    encoded_data = '080000000000000000000001000000000000001f0bd4060688a1800ae986e4840aebc924bb40b5bf3893263bf8b2d0373a34b8d359c5edd82311074760d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df510000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000001d5601c4475f2f6aa73d6a70a56f9c756f24d211a914cc7aff3fb80d2d8741c868f4966fe93b467d28f15befd438b7aa0e7b8fbf5f00ce1abe0cc4a0ddf9bcc7c45c9863b784f474dee3c0682a5aa4c982712b98fcd60f5e5d94038008a97e251300'

    data = encoded_data.decode('hex')
    s = tester.state()
    c = s.abi_contract(decode_code, language="solidity")

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
    signature = o2[4]
    assert signature == 'f4966fe93b467d28f15befd438b7aa0e7b8fbf5f00ce1abe0cc4a0ddf9bcc7c45c9863b784f474dee3c0682a5aa4c982712b98fcd60f5e5d94038008a97e251300'.decode('hex')
