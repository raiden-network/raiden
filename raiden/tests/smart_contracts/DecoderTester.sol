pragma solidity ^0.4.0;

import "raiden/NettingChannelLibrary.sol";

contract DecoderTester {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;


    bool public decoding_complete;

    modifier settleTimeoutNotTooLow(uint t) {
        if (t < 6) throw;
        _;
    }

    modifier after_decoding() {
        if (!decoding_complete) {
            throw;
        }
        _;
    }

    function DecoderTester(
        address assetAddress,
        address participant1,
        address participant2,
        uint timeout)
        settleTimeoutNotTooLow(timeout)
    {
        if (participant1 == participant2) {
            throw;
        }

        data.participants[0].nodeAddress = participant1;
        data.participants[1].nodeAddress = participant2;

        data.token = Token(assetAddress);
        data.settleTimeout = timeout;
    }

    function testDecodeTransfer(bytes signed_transfer) returns (bool) {
        data.closeSingleTransfer(msg.sender, signed_transfer);
        decoding_complete = true;
        return true;
    }

    function decodedNonce() after_decoding constant returns (uint64) {
        return data.participants[0].nonce;
    }

    function decodedAsset() after_decoding constant returns (address) {
        return data.participants[0].asset;
    }

    function decodedRecipient() after_decoding constant returns (address) {
        return data.participants[0].recipient;
    }

    function decodedAmount() after_decoding constant returns (uint256) {
        return data.participants[0].transferredAmount;
    }

    function decodedLocksroot() after_decoding constant returns (bytes32) {
        return data.participants[0].locksroot;
    }

    function decodedSecret() after_decoding constant returns (bytes32) {
        return data.participants[0].secret;
    }

    function decodedExpiration() after_decoding constant returns (uint256) {
        return data.participants[0].expiration;
    }
}
