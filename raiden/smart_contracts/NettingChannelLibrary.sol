pragma solidity ^0.4.0;

import "./Token.sol";

library NettingChannelLibrary {
    struct Participant
    {
        address node_address;

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

        // A mapping to keep track of locks that have been withdrawn.
        mapping(bytes32 => bool) withdrawn_locks;
    }

    struct Data {
        uint settle_timeout;
        uint opened;
        uint closed;
        uint settled;
        address closing_address;
        Token token;
        Participant[2] participants;
        mapping(address => uint8) participant_index;
        bool updated;
    }


    modifier notSettledButClosed(Data storage self) {
        if (self.settled > 0 || self.closed == 0)
            throw;
        _;
    }

    modifier stillTimeout(Data storage self) {
        if (self.closed + self.settle_timeout < block.number)
            throw;
        _;
    }

    modifier timeoutOver(Data storage self) {
        if (self.closed + self.settle_timeout > block.number)
            throw;
        _;
    }

    modifier channelSettled(Data storage self) {
        if (self.settled == 0)
            throw;
        _;
    }

    function isValidNonce(Data storage self, uint64 nonce)
        private
        returns (bool)
    {
        return (
            nonce >= self.opened * (2 ** 32) &&
            nonce < (self.opened + 1) * (2 ** 32)
        );
    }

    /// @notice Deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param amount The amount to be deposited to the address
    /// @return Success if the transfer was successful
    /// @return The new balance of the invoker
    function deposit(Data storage self, uint256 amount)
        returns (bool success, uint256 balance)
    {
        uint8 index;

        if (self.closed != 0) {
            throw;
        }

        if (self.token.balanceOf(msg.sender) < amount) {
            throw;
        }

        index = index_or_throw(self, msg.sender);
        Participant storage participant = self.participants[index];

        success = self.token.transferFrom(msg.sender, this, amount);
        if (success == true) {
            balance = participant.balance;
            balance += amount;
            participant.balance = balance;

            if (self.opened == 0) {
                self.opened = block.number;
            }

            return (true, balance);
        }

        return (false, 0);
    }

    /// @notice Close a channel between two parties that was used bidirectionally
    /// @param their_transfer The latest known transfer of the other participant
    ///                       to the channel. Can also be empty, in which case
    ///                       we are attempting to close a channel without any
    ///                       transfers.
    function close(Data storage self, bytes their_transfer)
    {
        uint closer_index;
        uint counterparty_index;
        bytes memory transfer_raw;
        uint64 nonce;
        address transfer_address;
        bytes32 locksroot;
        uint256 transferred_amount;

        // close can be called only once
        if (self.closed > 0) {
            throw;
        }

        // Only a participant can call close
        closer_index = index_or_throw(self, msg.sender);

        self.closing_address = msg.sender;
        self.closed = block.number;

        // Only the closing party can provide a transfer from the counterparty,
        // and only when this function is called, i.e. this value can not be
        // updated afterwards.

        // An empty value means that the closer never received a transfer, or
        // he is intentionally not providing the latest transfer, in which case
        // the closing party is going to lose the tokens that were transferred
        // to him.
        if (their_transfer.length != 0) {
            (transfer_raw, transfer_address) = getTransferRawAddress(their_transfer);
            counterparty_index = index_or_throw(self, transfer_address);

            // only a message from the counter party is valid
            if (closer_index == counterparty_index) {
                throw;
            }

            // update the structure of the counterparty with its data provided
            // by the closing node
            Participant storage counterparty = self.participants[counterparty_index];

            (nonce, locksroot, transferred_amount) = decodeTransfer(transfer_raw);

            // only accept messages with a valid nonce
            if (!isValidNonce(self, nonce)) {
                throw;
            }

            counterparty.nonce = nonce;
            counterparty.locksroot = locksroot;
            counterparty.transferred_amount = transferred_amount;
        }

    }

    /// @notice Updates counter party transfer after closing.
    /// @param their_transfer The transfer the counterparty believes is the
    ///                       valid state for the first participant.
    function updateTransfer(Data storage self, bytes their_transfer)
        notSettledButClosed(self)
        stillTimeout(self)
    {
        address transfer_address;
        bytes32 locksroot;
        bytes memory transfer_raw;
        uint256 transferred_amount;
        uint64 nonce;
        uint8 caller_index;
        uint8 closer_index;

        // updateTransfer can be called by the counter party only once
        if (self.updated) {
            throw;
        }
        self.updated = true;

        // Only a participant can call updateTransfer (#293 for third parties)
        caller_index = index_or_throw(self, msg.sender);

        // The closer is not allowed to call updateTransfer
        if (self.closing_address == msg.sender) {
            throw;
        }

        (transfer_raw, transfer_address) = getTransferRawAddress(their_transfer);

        // Counter party can only update the closer transfer
        if (transfer_address != self.closing_address) {
            throw;
        }

        // Update the structure of the closer with its data provided by the
        // counterparty
        closer_index = 1 - caller_index;

        (nonce, locksroot, transferred_amount) = decodeTransfer(transfer_raw);

        // only accept messages with a valid nonce
        if (!isValidNonce(self, nonce)) {
            throw;
        }

        self.participants[closer_index].nonce = nonce;
        self.participants[closer_index].locksroot = locksroot;
        self.participants[closer_index].transferred_amount = transferred_amount;
    }

    /// @notice Unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param locked_encoded The lock
    /// @param merkle_proof The merkle proof
    /// @param secret The secret
    function withdraw(Data storage self, bytes locked_encoded, bytes merkle_proof, bytes32 secret)
        notSettledButClosed(self)
    {
        uint amount;
        uint8 index;
        uint64 expiration;
        bytes32 h;
        bytes32 hashlock;

        // Check if msg.sender is a participant and select the partner (for
        // third party unlock see #541)
        index = 1 - index_or_throw(self, msg.sender);
        Participant storage counterparty = self.participants[index];

        // An empty locksroot means there are no pending locks
        if (counterparty.locksroot == 0) {
            throw;
        }

        (expiration, amount, hashlock) = decodeLock(locked_encoded);

        // A lock can be withdrawn only once per participant
        if (counterparty.withdrawn_locks[hashlock]) {
            throw;
        }
        counterparty.withdrawn_locks[hashlock] = true;

        if (expiration < block.number) {
            throw;
        }

        if (hashlock != sha3(secret)) {
            throw;
        }

        h = computeMerkleRoot(locked_encoded, merkle_proof);

        if (counterparty.locksroot != h) {
            throw;
        }

        // This implementation allows for each transfer to be set only once, so
        // it's safe to update the transferred_amount in place.
        //
        // Once third parties are allowed to update the counter party transfer
        // (#293, #182) the locksroot may change, if the locksroot change the
        // transferred_amount must be reset and locks must be re-withdrawn, so
        // this is also safe.
        //
        // This may be problematic if an update changes the transferred_amount
        // but not the locksroot, since the locks don't need to be
        // re-withdrawn, the difference in the transferred_amount must be
        // accounted for.
        counterparty.transferred_amount += amount;
    }

    function computeMerkleRoot(bytes lock, bytes merkle_proof)
        internal
        constant
        returns (bytes32)
    {
        if (merkle_proof.length % 32 != 0) {
            throw;
        }

        uint i;
        bytes32 h;
        bytes32 el;

        h = sha3(lock);
        for (i = 32; i <= merkle_proof.length; i += 32) {
            assembly {
                el := mload(add(merkle_proof, i))
            }

            if (h < el) {
                h = sha3(h, el);
            } else {
                h = sha3(el, h);
            }
        }

        return h;
    }

    /// @notice Settles the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return The participants with netted balances
    function settle(Data storage self)
        notSettledButClosed(self)
        timeoutOver(self)
    {
        uint8 closing_index;
        uint8 counter_index;
        uint256 total_deposit;
        uint256 counter_net;
        uint256 closer_amount;
        uint256 counter_amount;

        self.settled = block.number;

        closing_index = index_or_throw(self, self.closing_address);
        counter_index = 1 - closing_index;

        Participant storage closing_party = self.participants[closing_index];
        Participant storage counter_party = self.participants[counter_index];

        counter_net = (
            counter_party.balance
            + closing_party.transferred_amount
            - counter_party.transferred_amount
        );

        // Direct token transfers done through the token `transfer` function
        // cannot be accounted for, these superfluous tokens will be burned,
        // this is because there is no way to tell which participant (if any)
        // had ownership over the token.
        total_deposit = closing_party.balance + counter_party.balance;

        // When the closing party does not provide the counter party transfer,
        // the `counter_net` may be larger than the `total_deposit`, without
        // the min the token transfer fail and the token is locked.
        counter_amount = min(counter_net, total_deposit);

        // When the counter party does not provide the closing party transfer,
        // then `counter_amount` may be negative and the transfer fails, force
        // the value to 0.
        counter_amount = max(counter_amount, 0);

        // At this point `counter_amount` is between [0,total_deposit], so this
        // is safe.
        closer_amount = total_deposit - counter_amount;

        if (counter_amount > 0) {
            if (!self.token.transfer(counter_party.node_address, counter_amount)) {
                throw;
            }
        }

        if (closer_amount > 0) {
            if (!self.token.transfer(closing_party.node_address, closer_amount)) {
                throw;
            }
        }

        kill(self);
    }

    function getTransferRawAddress(bytes memory signed_transfer) internal returns (bytes memory, address) {
        uint signature_start;
        uint length;
        bytes memory signature;
        bytes memory transfer_raw;
        bytes32 transfer_hash;
        address transfer_address;

        length = signed_transfer.length;
        signature_start = length - 65;
        signature = slice(signed_transfer, signature_start, length);
        transfer_raw = slice(signed_transfer, 0, signature_start);

        transfer_hash = sha3(transfer_raw);
        var (r, s, v) = signatureSplit(signature);
        transfer_address = ecrecover(transfer_hash, v, r, s);

        return (transfer_raw, transfer_address);
    }

    // NOTES:
    //
    // - The EVM is a big-endian, byte addressing machine, with 32bytes/256bits
    //   words.
    // - The Ethereum Contract ABI specifies that variable length types have a
    //   32bytes prefix to define the variable size.
    // - Solidity has additional data types that are narrower than 32bytes
    //   (e.g. uint128 uses a half word).
    // - Solidity uses the *least-significant* bits of the word to store the
    //   values of a narrower type.
    //
    // GENERAL APPROACH:
    //
    // Add to the message pointer the number of bytes required to move the
    // address so that the target data is at the end of the 32bytes word.
    //
    // EXAMPLE:
    //
    // To decode the cmdid, consider this initial state:
    //
    //
    //     v- pointer word start
    //     [ 32 bytes length prefix ][ cmdid ] ----
    //                              ^- pointer word end
    //
    //
    // Because the cmdid has 1 byte length the type uint8 is used, the decoder
    // needs to move the pointer so the cmdid is at the end of the pointer
    // word.
    //
    //
    //             v- pointer word start [moved 1byte ahead]
    //     [ 32 bytes length prefix ][ cmdid ] ----
    //                                       ^- pointer word end
    //
    //
    // Now the data of the cmdid can be loaded to the uint8 variable.
    //
    // REFERENCES:
    // - https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI
    // - http://solidity.readthedocs.io/en/develop/assembly.html

    function decodeTransfer(bytes transfer_raw)
        internal
        returns (uint64 nonce, bytes32 locksroot, uint256 transferred_amount)
    {
        uint cmdid = uint(transfer_raw[0]);

        if (cmdid == 5) {
            return decodeDirectTransfer(transfer_raw);
        } else if (cmdid == 7) {
            return decodeMediatedTransfer(transfer_raw);
        } else if (cmdid == 8) {
            return decodeRefundTransfer(transfer_raw);
        }

        throw;
    }

    function decodeDirectTransfer(bytes memory message)
        private
        returns (uint64 nonce, bytes32 locksroot, uint256 transferred_amount)
    {
        // size of the raw message without the signature
        if (message.length != 124) {
            throw;
        }

        // Message format:
        // [0:1] cmdid
        // [1:4] pad
        // [4:12] nonce
        // [12:20] identifier
        // [20:40] token
        // [40:60] recipient
        // [60:92] transferred_amount
        // [92:124] optional_locksroot
        assembly {
            nonce := mload(add(message, 12))
            transferred_amount := mload(add(message, 92))
            locksroot := mload(add(message, 124))
        }
    }

    function decodeMediatedTransfer(bytes memory message)
        private
        returns (uint64 nonce, bytes32 locksroot, uint256 transferred_amount)
    {
        // size of the raw message without the signature
        if (message.length != 268) {
            throw;
        }

        // Message format:
        // [0:1] cmdid
        // [1:4] pad
        // [4:12] nonce
        // [12:20] identifier
        // [20:28] expiration
        // [28:48] token
        // [48:68] recipient
        // [68:88] target
        // [88:108] initiator
        // [108:140] locksroot
        // [140:172] hashlock
        // [172:204] transferred_amoun
        // [204:236] amount
        // [236:268] fee
        assembly {
            nonce := mload(add(message, 12))
            locksroot := mload(add(message, 140))
            transferred_amount := mload(add(message, 204))
        }
    }

    function decodeRefundTransfer(bytes memory message)
        private
        returns (uint64 nonce, bytes32 locksroot, uint256 transferred_amount)
    {
        // size of the raw message without the signature
        if (message.length != 196) {
            throw;
        }

        // Message format:
        // [0:1] cmdid
        // [1:4] pad
        // [4:12] nonce
        // [12:20] identifier
        // [20:28] expiration
        // [28:48] token
        // [48:68] recipient
        // [68:100] locksroot
        // [100:132] transferred_amount
        // [132:164] amount
        // [164:196] hashlock
        assembly {
            nonce := mload(add(message, 12))
            locksroot := mload(add(message, 100))
            transferred_amount := mload(add(message, 132))
        }
    }

    function decodeLock(bytes lock) internal returns (uint64 expiration, uint amount, bytes32 hashlock) {
        if (lock.length != 72) {
            throw;
        }

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

    function signatureSplit(bytes signature) private returns (bytes32 r, bytes32 s, uint8 v) {
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
            v := and(mload(add(signature, 65)), 1)
        }
        // old geth sends a `v` value of [0,1], while the new, in line with the YP sends [27,28]
        if(v < 27) v += 27;
    }

    function slice(bytes a, uint start, uint end) private returns (bytes n) {
        if (a.length < end) {
            throw;
        }
        if (start < 0) {
            throw;
        }

        n = new bytes(end - start);
        for (uint i = start; i < end; i++) { //python style slice
            n[i - start] = a[i];
        }
    }

    function index_or_throw(Data storage self, address participant_address) private returns (uint8) {
        uint8 n;
        // Return index of participant, or throw
        n = self.participant_index[participant_address];
        if (n == 0) {
            throw;
        }
        return n - 1;
    }

    function min(uint a, uint b) constant internal returns (uint) {
        return a > b ? b : a;
    }

    function max(uint a, uint b) constant internal returns (uint) {
        return a > b ? a : b;
    }

    function kill(Data storage self) channelSettled(self) {
        selfdestruct(0x00000000000000000000);
    }
}
