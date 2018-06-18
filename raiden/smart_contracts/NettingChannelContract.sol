pragma solidity ^0.4.23;

import "./NettingChannelLibrary.sol";

contract NettingChannelContract {
    string constant public contract_version = "0.2._";

    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    event ChannelNewBalance(
        address registry_address,
        address token_address,
        address participant,
        uint balance
    );

    event ChannelClosed(address registry_address, address closing_address);
    event TransferUpdated(address node_address);
    event ChannelSettled(address registry_address);

    event ChannelSecretRevealed(
        address registry_address,
        bytes32 secret,
        address receiver_address
    );

    modifier settleTimeoutValid(uint t) {
        require(t >= 6 && t <= 2700000);
        _;
    }

    constructor(
        address registry_address,
        address token_address,
        address participant1,
        address participant2,
        uint timeout
    )
        public
        settleTimeoutValid(timeout)
    {
        require(participant1 != participant2);

        data.participants[0].node_address = participant1;
        data.participants[1].node_address = participant2;
        data.participant_index[participant1] = 1;
        data.participant_index[participant2] = 2;

        data.registry_address = registry_address;
        data.token = Token(token_address);
        data.settle_timeout = timeout;
        data.opened = block.number;
    }

    /// @notice Caller sets total deposit in their channel
    /// @param total_deposit The total_deposit to set
    /// @return True if deposit is successful.
    function setTotalDeposit(uint256 total_deposit)
        public
        returns (bool)
    {
        bool success;
        uint256 balance;

        (success, balance) = data.setTotalDeposit(total_deposit);

        if (success == true) {
            emit ChannelNewBalance(data.registry_address, data.token, msg.sender, balance);
        }

        return success;
    }

    /// @notice Get the address and balance of both partners in a channel.
    /// @return The address and balance pairs.
    function addressAndBalance()
        public
        constant
        returns (address participant1, uint balance1, address participant2, uint balance2)
    {
        NettingChannelLibrary.Participant storage node1 = data.participants[0];
        NettingChannelLibrary.Participant storage node2 = data.participants[1];

        participant1 = node1.node_address;
        balance1 = node1.balance;
        participant2 = node2.node_address;
        balance2 = node2.balance;
    }

    /// @notice Close the channel. Can only be called by a participant in the channel.
    function close(
        uint64 nonce,
        uint256 transferred_amount,
        uint256 locked_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    )
        public
    {
        data.close(
            nonce,
            transferred_amount,
            locked_amount,
            locksroot,
            extra_hash,
            signature
        );
        emit ChannelClosed(data.registry_address, msg.sender);
    }

    /// @notice Dispute the state after closing, called by the counterparty (the
    ///         participant who did not close the channel).
    function updateTransfer(
        uint64 nonce,
        uint256 transferred_amount,
        uint256 locked_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    )
        public
    {
        data.updateTransfer(
            nonce,
            transferred_amount,
            locked_amount,
            locksroot,
            extra_hash,
            signature
        );
        emit TransferUpdated(msg.sender);
    }

    /// @notice Unlock a locked transfer.
    /// @param locked_encoded The locked transfer to be unlocked.
    /// @param merkle_proof The merke_proof for the locked transfer.
    /// @param secret The secret to unlock the locked transfer.
    function unlock(bytes locked_encoded, bytes merkle_proof, bytes32 secret) public {
        // throws if sender is not a participant
        data.unlock(locked_encoded, merkle_proof, secret);
        emit ChannelSecretRevealed(data.registry_address, secret, msg.sender);
    }

    /// @notice Settle the transfers and balances of the channel and pay out to
    ///         each participant. Can only be called after the channel is closed
    ///         and only after the number of blocks in the settlement timeout
    ///         have passed.
    function settle() public {
        data.settle();
        emit ChannelSettled(data.registry_address);
    }

    /// @notice Returns the number of blocks until the settlement timeout.
    /// @return The number of blocks until the settlement timeout.
    function settleTimeout() public constant returns (uint) {
        return data.settle_timeout;
    }

    /// @notice Returns the address of the token.
    /// @return The address of the token.
    function tokenAddress() public constant returns (address) {
        return data.token;
    }

    /// @notice Returns the block number for when the channel was opened.
    /// @return The block number for when the channel was opened.
    function opened() public constant returns (uint) {
        return data.opened;
    }

    /// @notice Returns the block number for when the channel was closed.
    /// @return The block number for when the channel was closed.
    function closed() public constant returns (uint) {
        return data.closed;
    }

    /// @notice Returns the address of the closing participant.
    /// @return The address of the closing participant.
    function closingAddress() public constant returns (address) {
        return data.closing_address;
    }

    function () public { revert(); }
}
