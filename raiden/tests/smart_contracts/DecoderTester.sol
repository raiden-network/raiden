pragma solidity ^0.4.0;

import "raiden/NettingChannelLibrary.sol";

contract DecoderTester {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    // temporary, just to check if we can query a contract attribute from tests
    uint256 public foo;

    modifier settleTimeoutNotTooLow(uint t) {
        if (t < 6) throw;
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
        foo = 19;
    }

    function testCloseSingleTransfer(
        bytes signed_transfer,
        uint64 expected_nonce,
        address expected_address,
        address expected_recipient,
        uint256 expected_amount,
        bytes32 expected_locksroot,
        bytes32 expected_secret
    ) returns (bool) {
        data.closeSingleTransfer(msg.sender, signed_transfer);
        return true;
    }

}
