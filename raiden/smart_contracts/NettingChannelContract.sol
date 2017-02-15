pragma solidity ^0.4.0;

import "./NettingChannelLibrary.sol";

contract NettingChannelContract {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    event ChannelNewBalance(address token_address, address participant, uint balance, uint block_number);
    event ChannelClosed(address closing_address, uint block_number);
    event TransferUpdated(address node_address, uint block_number);
    event ChannelSettled(uint block_number);
    event ChannelSecretRevealed(bytes32 secret);

    modifier settleTimeoutNotTooLow(uint t) {
        if (t < 6) throw;
        _;
    }

    function NettingChannelContract(
        address token_address,
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

        data.token = Token(token_address);
        data.settle_timeout = timeout;
    }

    /// @notice Caller makes a deposit into their channel balance.
    /// @param amount The amount caller wants to deposit.
    /// @return True if deposit is successful.
    function deposit(uint256 amount) returns (bool) {
        bool success;
        uint256 balance;

        (success, balance) = data.deposit(msg.sender, this, amount);

        if (success == true) {
            ChannelNewBalance(data.token, msg.sender, balance, data.opened);
        }

        return success;
    }

    /// @notice Get the address of the channel partner.
    /// @param participant_address The address of one participant.
    /// @return The address of the partner to that participant.
    function partner(address participant_address) constant returns (address) {
        return data.partner(participant_address);
    }

    /// @notice Get the address and balance of both partners in a channel.
    /// @return The address and balance pairs.
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

    /// @notice Get the amount one partner has transferred to the other partner.
    /// @param participant The address of one partner.
    /// @return The amount one partner has transferred to the other.
    function transferredAmount(address participant) constant returns (uint) {
        return data.transferredAmount(participant);
    }

    /// @notice Close the channel. Can only be called by a participant in the channel.
    /// @param theirs_encoded The last transfer recieved from our partner.
    /// @param ours_encoded The last transfer sent to our partner.
    function close(bytes theirs_encoded, bytes ours_encoded) {
        data.close(msg.sender, theirs_encoded, ours_encoded);
        ChannelClosed(msg.sender, data.closed);
    }

    /// @notice Dispute the state after closing, called by the counterparty (the
    ///         participant who did not close the channel).
    /// @param theirs_encoded The transfer the counterparty believes is the valid
    ///                       state of the first participant.
    function updateTransfer(bytes theirs_encoded) {
        data.updateTransfer(msg.sender, theirs_encoded);
        TransferUpdated(msg.sender, block.number);
    }

    /// @notice Unlock a locked transfer.
    function unlock(bytes locked_encoded, bytes merkle_proof, bytes32 secret) {
        data.unlock(msg.sender, locked_encoded, merkle_proof, secret);
        ChannelSecretRevealed(secret);
    }

    /// @notice Settle the transfers and balances of the channel and pay out to
    ///         each participant. Can only be called after the channel is closed
    ///         and only after the number of blocks in the settlement timeout
    ///         have passed.
    function settle() {
        data.settle(msg.sender);
        ChannelSettled(data.settled);
    }

    /// @notice Returns the number of blocks until the settlement timeout.
    function settleTimeout() constant returns (uint) {
        return data.settle_timeout;
    }

    /// @notice Returns the address of the token.
    function tokenAddress() constant returns (address) {
        return data.token;
    }

    /// @notice Returns the block number for when the channel was opened.
    function opened() constant returns (uint) {
        return data.opened;
    }

    /// @notice Returns the block number for when the channel was closed.
    function closed() constant returns (uint) {
        return data.closed;
    }

    /// @notice Returns the block number for when the channel was settled.
    function settled() constant returns (uint) {
        return data.settled;
    }

    /// @notice Returns the address of the closing participant.
    function closingAddress() constant returns (address) {
        return data.closing_address;
    }

    function () { throw; }
}
