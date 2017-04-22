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
}
