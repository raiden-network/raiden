pragma solidity ^0.4.0;

import "raiden/NettingChannelLibrary.sol";

contract LockDecoderTester is NettingChannelLibrary {

    function testDecodeTransfer(bytes locked_encoded)
        returns (uint64 expiration, uint amount, bytes32 hashlock)
    {
            return decodeLock(locked_encoded);
    }
}
