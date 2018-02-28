pragma solidity ^0.4.17;

import "./Token.sol";
import "./Utils.sol";

contract TokenNetwork is Utils {

    /*
     *  Data structures
     */

    string constant public contract_version = "0.3._";

    // Instance of the token used as digital currency by the channels
    Token public token;

    // Channel identifier is a uint256, incremented after each new channel
    mapping (uint256 => Channel) public channels;

    // Used for determining the next channel identifier
    // Start from 1 instead of 0, otherwise the first channel will have an additional
    // 15000 gas cost than the rest
    uint256 public last_channel_index = 1;

    // The ClosingRequest identfier must be THE SAME as the channel identifier (mapping key) from `channels`
    mapping (uint256 => ClosingRequest) public closing_requests;

    struct Participant
    {
        // Total amount of token transferred to this smart contract through the
        // `deposit` function, note that direct token transfer cannot be
        // tracked and will be burned.
        uint256 balance;

        // The latest known merkle root of the pending hash-time locks, used to
        // validate the withdrawn proofs.
        bytes32 locksroot;

        // The latest known transferred_amount from this node to the other
        // participant, used to compute the net balance on settlement.
        uint256 transferred_amount;

        // Value used to order transfers and only accept the latest on calls to
        // update, this will only be relevant after either #182 or #293 is
        // implemented.
        uint64 nonce;

        // This value is set to True after the channel has been opened.
        // This is an efficient way to mark the channel participants without doing a deposit.
        // This is uint8 and it gets packed with the nonce.
        bool initialized;

        // A mapping to keep track of locks that have been withdrawn.
        mapping(bytes32 => bool) withdrawn_locks;
    }

    struct Channel {
        // We also use the settle_timeout to verify that
        // the channel is open
        uint256 settle_timeout;
        mapping(address => Participant) participants;
    }

    struct ClosingRequest {
        address closing_address;

        // Block number at which the settlement window ends.
        uint256 settle_block_number;
    }

    /*
     *  Events
     */

    event ChannelOpened(
        uint256 channel_identifier,
        address participant1,
        address participant2,
        uint256 settle_timeout
    );

    event ChannelNewBalance(uint256 channel_identifier, address participant, uint256 balance);

    event ChannelClosed(uint256 channel_identifier, address closing_address);

    event ChannelUnlocked(uint256 channel_identifier, address participant, uint256 transferred_amount);

    event TransferUpdated(uint256 channel_identifier, address caller);

    event ChannelSettled(uint256 channel_identifier);

    /*
     * Modifiers
     */

    modifier isClosed(uint256 channel_identifier) {
        require(closing_requests[channel_identifier].settle_block_number > 0);
        _;
    }

    modifier stillTimeout(uint256 channel_identifier) {
        require(closing_requests[channel_identifier].settle_block_number >= block.number);
        _;
    }

    modifier timeoutOver(uint256 channel_identifier) {
        require(closing_requests[channel_identifier].settle_block_number < block.number);
        _;
    }

    // Note: we use the settleTimeout to check if the channel is open. It must always be > 0.
    modifier settleTimeoutValid(uint256 timeout) {
        require(timeout >= 6 && timeout <= 2700000);
        _;
    }

    /*
     *  Constructor
     */

    function TokenNetwork(address _token_address) public {
        require(_token_address != 0x0);
        require(contractExists(_token_address));

        token = Token(_token_address);

        // Check if the contract is indeed a token contract
        require(token.totalSupply() > 0);
    }

    /*
     *  Public functions
     */

    /// @notice Opens a new channel between `participant1` and `participant2`.
    /// Can be called by anyone.
    function openChannel(
        address participant1,
        address participant2,
        uint256 settle_timeout)
        settleTimeoutValid(settle_timeout)
        public
        returns (uint256)
    {
        require(participant1 != 0x0);
        require(participant2 != 0x0);
        require(participant1 != participant2);

        // Increase channel index counter
        last_channel_index += 1;

        require(channels[last_channel_index].settle_timeout == 0);
        require(!channels[last_channel_index].participants[participant1].initialized);
        require(!channels[last_channel_index].participants[participant2].initialized);

        // Store channel information
        channels[last_channel_index] = Channel({settle_timeout: settle_timeout});

        // Mark the channel participants
        // We use this in deposit to ensure the beneficiary is a channel participant
        channels[last_channel_index].participants[participant1].initialized = true;
        channels[last_channel_index].participants[participant2].initialized = true;

        ChannelOpened(last_channel_index, participant1, participant2, settle_timeout);

        return last_channel_index;
    }

    /// @notice Deposit tokens to an already existent channel.
    /// Can be called by anyone.
    function deposit(
        uint256 channel_identifier,
        address beneficiary,
        uint256 added_amount)
        public
    {
        Channel storage channel = channels[channel_identifier];

        // Channel must be open and beneficiary must be one of the participants
        require(channel.participants[beneficiary].initialized);

        // Channel cannot be closed
        require(closing_requests[channel_identifier].settle_block_number == 0);

        // Sender should have enough balance
        // TODO: is this necessary? token.transfer should fail anyway if implemented correctly
        require(token.balanceOf(msg.sender) >= added_amount);

        // Change the state
        channel.participants[beneficiary].balance += added_amount;

        // Do the transfer
        require(token.transferFrom(msg.sender, address(this), added_amount));

        ChannelNewBalance(channel_identifier, beneficiary, channel.participants[beneficiary].balance);
    }

    /// @notice Close a channel between two parties that was used bidirectionally.
    /// Only a participant may close the channel, providing a balance proof signed by its partner. Callable only once.
    /// @param channel_identifier The channel identifier.
    /// @param nonce Strictly monotonic value used to order transfers.
    /// @param transferred_amount Total amount of tokens transferred by the channel partner
    /// to the channel participant who calls the function.
    /// @param locksroot Root of the partner's merkle tree of all pending lock lockhashes.
    /// @param additional_hash Computed from the message. Used for message authentication.
    /// @param signature Partner's signature of the balance proof data.
    function closeChannel(
        uint256 channel_identifier,
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 additional_hash,
        bytes signature)
        public
    {
        address partner_address;

        // Close can be called only once
        require(closing_requests[channel_identifier].settle_block_number == 0);

        Channel storage channel = channels[channel_identifier];

        // Only a participant may close the channel.
        require(channel.participants[msg.sender].initialized);

        // Store the closing request data
        closing_requests[channel_identifier].closing_address = msg.sender;
        closing_requests[channel_identifier].settle_block_number = channel.settle_timeout + block.number;

        // An empty value means that the closer never received a transfer, or
        // he is intentionally not providing the latest transfer, in which case
        // the closing party is going to lose the tokens that were transferred
        // to him.
        partner_address = recoverAddressFromSignature(
            channel_identifier,
            nonce,
            transferred_amount,
            locksroot,
            additional_hash,
            signature
        );

        // Signature must be from the channel partner
        require(msg.sender != partner_address);

        updateParticipantStruct(
            channel_identifier,
            partner_address,
            nonce,
            locksroot,
            transferred_amount
        );

        ChannelClosed(channel_identifier, msg.sender);
    }

    /// @notice Called on a closed channel, the function allows the non-closing participant
    /// to provide the last balance proof, which modifies the closing participant's state.
    /// Can be called multiple times, by anyone.
    function updateTransfer(
        uint256 channel_identifier,
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 additional_hash,
        bytes signature)
        isClosed(channel_identifier)
        stillTimeout(channel_identifier)
        public
    {
        address partner_address;

        partner_address = recoverAddressFromSignature(
            channel_identifier,
            nonce,
            transferred_amount,
            locksroot,
            additional_hash,
            signature
        );

        uint64 old_nonce = channels[channel_identifier].participants[partner_address].nonce;
        bytes32 old_locksroot = channels[channel_identifier].participants[partner_address].locksroot;

        // This will reset the transferred amount, invalidating any unlocked locks that were
        // unlocked but not included in the new locksroot
        updateParticipantStruct(
            channel_identifier,
            partner_address,
            nonce,
            locksroot,
            transferred_amount
        );

        // Clean up storage for the old (nonce, locksroot)
        // after the locksroot has been replaced.
        // This cannot be used anymore to unlock locks anyway.
        bytes32 old_key = keccak256(old_nonce, old_locksroot);
        delete channels[channel_identifier].participants[partner_address].withdrawn_locks[old_key];

        TransferUpdated(channel_identifier, msg.sender);
    }

    /// @notice Unlocks a pending transfer and increases the partner's transferred amount
    /// with the transfer value. A lock can be unlocked only once per participant.
    // Anyone can call unlock a transfer on behalf of a channel participant.
    function unlock(
        uint256 channel_identifier,
        address partner,
        uint64 expiration_block,
        uint256 locked_amount,
        bytes32 hashlock,
        bytes merkle_proof,
        bytes32 secret)
        stillTimeout(channel_identifier)
        public
    {
        bytes32 key;
        bytes32 computed_locksroot;
        bytes memory locked_encoded;

        // Check that the partner is a channel participant.
        require(channels[channel_identifier].participants[partner].initialized);

        Participant storage partner_state = channels[channel_identifier].participants[partner];

        // An empty locksroot means there are no pending locks
        require(partner_state.locksroot != 0);

        // The lock must not have expired, it does not matter how far in the
        // future it would have expired
        require(expiration_block > block.number);
        require(hashlock == keccak256(secret));

        locked_encoded = encodeLock(expiration_block, locked_amount, hashlock);
        computed_locksroot = computeMerkleRoot(locked_encoded, merkle_proof);

        // Note that unlocked locks have to be re-unlocked after a `transferUpdate` with a
        // locksroot that does not contain this lock.
        require(partner_state.locksroot == computed_locksroot);

        // A lock can be withdrawn only once per participant
        key = keccak256(partner_state.nonce, partner_state.locksroot);
        require(!partner_state.withdrawn_locks[key]);
        partner_state.withdrawn_locks[key] = true;

        // Finally change the amount of owed tokens
        // This implementation allows for each transfer to be set only once, so
        // it's safe to update the transferred_amount in place.
        //
        partner_state.transferred_amount += locked_amount;

        ChannelUnlocked(channel_identifier, partner, partner_state.transferred_amount);
    }

    /// @notice Settles the balance between the two parties
    function settleChannel(
        uint256 channel_identifier,
        address participant1,
        address participant2)
        isClosed(channel_identifier)
        timeoutOver(channel_identifier)
        public
    {
        uint256 participant1_amount;
        uint256 participant2_amount;
        uint256 total_deposit;

        Participant memory participant1_state = channels[channel_identifier].participants[participant1];
        Participant memory participant2_state = channels[channel_identifier].participants[participant2];

        // Make sure the addresses are channel participant addresses
        require(participant1_state.initialized);
        require(participant2_state.initialized);

        // Direct token transfers done through the token `transfer` function
        // cannot be accounted for, these superfluous tokens will be burned,
        // this is because there is no way to tell which participant (if any)
        // had ownership over the token.
        total_deposit = participant1_state.balance + participant2_state.balance;

        participant1_amount = (
            participant1_state.balance
            + participant2_state.transferred_amount
            - participant1_state.transferred_amount
        );

        // To account for cases when participant2 does not provide participant1's balance proof
        // Therefore, participant1's transferred_amount will be lower than in reality
        participant1_amount = min(participant1_amount, total_deposit);

        // To account for cases when participant1 does not provide participant2's balance proof
        // Therefore, participant2's transferred_amount will be lower than in reality
        participant1_amount = max(participant1_amount, 0);

        // At this point `participant1_amount` is between [0,total_deposit], so this is safe.
        participant2_amount = total_deposit - participant1_amount;

        // Remove the channel data from storage
        delete channels[channel_identifier];
        delete closing_requests[channel_identifier];

        // Do the actual token transfers
        require(token.transfer(participant1, participant1_amount));
        require(token.transfer(participant2, participant2_amount));

        ChannelSettled(channel_identifier);
    }

    // TODO
    /*function cooperativeSettle(
        uint256 channel_identifier,
        uint256 balance1,
        uint256 balance2,
        bytes signature1,
        bytes signature2)
        public
    {

    }*/

    /*
     * Internal Functions
     */

    function updateParticipantStruct(
        uint256 channel_identifier,
        address participant,
        uint64 nonce,
        bytes32 locksroot,
        uint256 transferred_amount)
        internal
    {
        Channel storage channel = channels[channel_identifier];

        require(channel.participants[participant].initialized);
        require(nonce > channel.participants[participant].nonce);
        // Transfers can have 0 value
        require(transferred_amount >= channel.participants[participant].transferred_amount);

        // Note, locksroot may be 0x0 and it may not change between two balance proofs.

        // Update the partner's structure with the data provided
        // by the closing participant.
        channel.participants[participant].nonce = nonce;
        channel.participants[participant].locksroot = locksroot;
        channel.participants[participant].transferred_amount = transferred_amount;
    }

    function recoverAddressFromSignature(
        uint256 channel_identifier,
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 additional_hash,
        bytes signature
    )
        view
        internal
        returns (address)
    {
        require(signature.length == 65);

        bytes32 signed_hash = keccak256(
            nonce,
            transferred_amount,
            locksroot,
            channel_identifier,
            address(this),
            additional_hash
        );

        var (r, s, v) = signatureSplit(signature);
        return ecrecover(signed_hash, v, r, s);
    }

    function signatureSplit(bytes signature)
        pure
        internal
        returns (bytes32 r, bytes32 s, uint8 v)
    {
        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(signature, 65)), 0xff)
        }

        require(v == 27 || v == 28);
    }

    // TODO - implement this
    function encodeLock(
        uint64 expiration_block,
        uint256 amount,
        bytes32 hashlock)
        pure
        internal
        returns (bytes lock)
    {

    }

    // TODO - not used anymore now
    function decodeLock(bytes lock)
        pure
        internal
        returns (uint64 expiration, uint256 amount, bytes32 hashlock)
    {
        require(lock.length == 72);

        // Lock format:
        // [0:8] expiration
        // [8:40] amount
        // [40:72] hashlock
        assembly {
            expiration := mload(add(lock, 8))
            amount := mload(add(lock, 40))
            hashlock := mload(add(lock, 72))
        }
    }

    function computeMerkleRoot(bytes lock, bytes merkle_proof)
        pure
        internal
        returns (bytes32)
    {
        require(merkle_proof.length % 32 == 0);

        uint256 i;
        bytes32 h;
        bytes32 el;

        h = keccak256(lock);
        for (i = 32; i <= merkle_proof.length; i += 32) {
            assembly {
                el := mload(add(merkle_proof, i))
            }

            if (h < el) {
                h = keccak256(h, el);
            } else {
                h = keccak256(el, h);
            }
        }

        return h;
    }

    function min(uint256 a, uint256 b) pure internal returns (uint256)
    {
        return a > b ? b : a;
    }

    function max(uint256 a, uint256 b) pure internal returns (uint256)
    {
        return a > b ? a : b;
    }
}
