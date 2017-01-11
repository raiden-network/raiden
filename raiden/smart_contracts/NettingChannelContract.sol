pragma solidity ^0.4.0;

import "./NettingChannelLibrary.sol";

contract NettingChannelContract {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    event ChannelNewBalance(address asset_address, address participant, uint balance, uint block_number);
    event ChannelClosed(address closing_address, uint block_number);
    event TransferUpdated(address node_address, uint block_number);
    event ChannelSettled(uint block_number);
    event ChannelSecretRevealed(bytes32 secret);

    modifier settleTimeoutNotTooLow(uint t) {
        if (t < 6) throw;
        _;
    }

    function NettingChannelContract(
        address asset_address,
        address participant1,
        address participant2,
        uint timeout)
        settleTimeoutNotTooLow(timeout)
    {
        if (participant1 == participant2) {
            throw;
        }

        data.participants[0].node_address = participant1;
        data.participants[1].node_address = participant2;

        data.token = Token(asset_address);
        data.settle_timeout = timeout;
    }

    function deposit(uint256 amount) returns (bool) {
        bool success;
        uint256 balance;

        (success, balance) = data.deposit(msg.sender, this, amount);

        if (success == true) {
            ChannelNewBalance(data.token, msg.sender, balance, data.opened);
        }

        return success;
    }

    function partner(address one_address) constant returns (address) {
        return data.partner(one_address);
    }

    function addressAndBalance()
        constant
        returns (
        address participant1,
        uint balance1,
        address participant2,
        uint balance2)
    {
        return data.addressAndBalance();
    }

    function transferredAmount(address participant) constant returns (uint) {
        return data.transferredAmount(participant);
    }

    function close(bytes theirs_encoded, bytes ours_encoded) {
        data.close(msg.sender, theirs_encoded, ours_encoded);
        ChannelClosed(msg.sender, data.closed);
    }

    function updateTransfer(bytes theirs_encoded) {
        data.updateTransfer(msg.sender, theirs_encoded);
        TransferUpdated(msg.sender, block.number);
    }

    function unlock(bytes locked_encoded, bytes merkle_proof, bytes32 secret) {
        data.unlock(msg.sender, locked_encoded, merkle_proof, secret);
        ChannelSecretRevealed(secret);
    }

    function settle() {
        data.settle(msg.sender);
        ChannelSettled(data.settled);
    }

    function settleTimeout() constant returns (uint) {
        return data.settle_timeout;
    }

    function assetAddress() constant returns (address) {
        return data.token;
    }

    function opened() constant returns (uint) {
        return data.opened;
    }

    function closed() constant returns (uint) {
        return data.closed;
    }

    function settled() constant returns (uint) {
        return data.settled;
    }

    function closingAddress() constant returns (address) {
        return data.closing_address;
    }

    function () { throw; }
}
