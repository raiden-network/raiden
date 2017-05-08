pragma solidity ^0.4.0;

import "raiden/NettingChannelLibrary.sol";

contract DecoderTester {
    function decodeLock(bytes lock) returns (uint64 expiration, uint amount, bytes32 hashlock) {
        return NettingChannelLibrary.decodeLock(lock);
    }

    function getTransferRawAddress(bytes signed_transfer) returns (bytes transfer_raw, address signing_address) {
        return NettingChannelLibrary.getTransferRawAddress(signed_transfer);
    }

    function decodeTransfer(bytes transfer_raw) returns (uint64 nonce, bytes32 locksroot, uint256 transferred_amount) {
        return NettingChannelLibrary.decodeTransfer(transfer_raw);
    }
}
