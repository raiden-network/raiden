from ethereum import tester

from raiden.utils import privtoaddr
from raiden.encoding.signing import recover_publickey, address_from_key, sign

ec_code = '''
contract EcTest {
    function ecTest(bytes message, bytes sig) returns (address) {
        bytes32 hash = sha3(message);
        var(r, s, v) = sigSplit(sig);
        return ecrecover(hash, v, r, s);
    }
    function sigSplit(bytes message)  returns (bytes32 r, bytes32 s, uint8 v) {
        if (message.length != 65) throw;

        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(message, 32))
            s := mload(add(message, 64))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(message, 65)), 1)

        }
        // old geth sends a `v` value of [0,1], while the new, in line with the YP sends [27,28]
        if(v < 27) v += 27;
    }
}
'''


def test_ec():
    state = tester.state()
    assert state.block.number < 1150000
    state.block.number = 1158001
    assert state.block.number > 1150000
    ec = state.abi_contract(ec_code, language='solidity')

    INITIATOR_PRIVKEY = 'x' * 32
    INITIATOR_ADDRESS = privtoaddr(INITIATOR_PRIVKEY)

    msg = 'blabla'
    sig, pub = sign(msg, INITIATOR_PRIVKEY)

    # pure python recover
    sen = recover_publickey(msg, sig)
    assert address_from_key(sen) == INITIATOR_ADDRESS

    # solidity ecrecover
    sender = ec.ecTest(msg, sig)
    assert sender == INITIATOR_ADDRESS.encode('hex')
