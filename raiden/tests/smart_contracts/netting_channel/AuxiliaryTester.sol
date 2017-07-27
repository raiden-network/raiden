pragma solidity ^0.4.0;

import "raiden/NettingChannelLibrary.sol";

contract AuxiliaryTester {
    function min(uint a, uint b) constant returns (uint) {
        return NettingChannelLibrary.min(a, b);
    }

    function max(uint a, uint b) constant returns (uint) {
        return NettingChannelLibrary.max(a, b);
    }

    function computeMerkleRoot(bytes lock, bytes merkle_proof)
        constant
        returns (bytes32)
    {
        return NettingChannelLibrary.computeMerkleRoot(lock, merkle_proof);
    }

    function signatureSplit(bytes signature) returns (bytes32 r, bytes32 s, uint8 v) {
        return NettingChannelLibrary.signatureSplit(signature);
    }

    function recoverAddressFromSignature(
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    ) returns (address) {
        return NettingChannelLibrary.recoverAddressFromSignature(
            nonce,
            transferred_amount,
            locksroot,
            extra_hash,
            signature
        );
    }
}
