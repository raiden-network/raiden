pragma solidity ^0.4.16;

import "./Token.sol";

library NettingChannelLibrary {
    string constant public contract_version = "0.2._";

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
        address closing_address;
        address registry_address;
        Token token;
        Participant[2] participants;
        mapping(address => uint8) participant_index;
        bool updated;
    }


    modifier isClosed(Data storage self) {
        require(self.closed > 0);
        _;
    }

    modifier stillTimeout(Data storage self) {
        require(self.closed + self.settle_timeout >= block.number);
        _;
    }

    modifier timeoutOver(Data storage self) {
        require(self.closed + self.settle_timeout <= block.number);
        _;
    }

    /// @notice Deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param amount The amount to be deposited to the address
    /// @return Success if the transfer was successful
    /// @return The new balance of the invoker
    function deposit(Data storage self, uint256 amount)
        public
        returns (bool success, uint256 balance)
    {
        uint8 index;

        require(self.opened > 0);
        require(self.closed == 0);
        require(self.token.balanceOf(msg.sender) >= amount);

        index = index_or_throw(self, msg.sender);
        Participant storage participant = self.participants[index];

        success = self.token.transferFrom(msg.sender, this, amount);
        if (success == true) {
            balance = participant.balance;
            balance += amount;
            participant.balance = balance;

            return (true, balance);
        }

        return (false, 0);
    }

    /// @notice Close a channel between two parties that was used bidirectionally
    function close(
        Data storage self,
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    )
        public
    {
        address transfer_address;
        uint closer_index;
        uint counterparty_index;

        // close can be called only once
        require(self.closed == 0);
        self.closed = block.number;

        // Only a participant can call close
        closer_index = index_or_throw(self, msg.sender);
        self.closing_address = msg.sender;

        // Only the closing party can provide a transfer from the counterparty,
        // and only when this function is called, i.e. this value can not be
        // updated afterwards.

        // An empty value means that the closer never received a transfer, or
        // he is intentionally not providing the latest transfer, in which case
        // the closing party is going to lose the tokens that were transferred
        // to him.
        if (signature.length == 65) {
            transfer_address = recoverAddressFromSignature(
                nonce,
                transferred_amount,
                locksroot,
                extra_hash,
                signature 
            );

            counterparty_index = index_or_throw(self, transfer_address);
            require(closer_index != counterparty_index);

            // update the structure of the counterparty with its data provided
            // by the closing node
            Participant storage counterparty = self.participants[counterparty_index];
            counterparty.nonce = uint64(nonce);
            counterparty.locksroot = locksroot;
            counterparty.transferred_amount = transferred_amount;
        }
    }

    /// @notice Updates counter party transfer after closing.
    function updateTransfer(
        Data storage self,
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    )
        isClosed(self)
        stillTimeout(self)
        public
    {
        address transfer_address;
        uint8 caller_index;
        uint8 closer_index;

        // updateTransfer can be called by the counter party only once
        require(!self.updated);
        self.updated = true;

        // Only a participant can call updateTransfer (#293 for third parties)
        caller_index = index_or_throw(self, msg.sender);

        // The closer is not allowed to call updateTransfer
        require(self.closing_address != msg.sender);

        // Counter party can only update the closer transfer
        transfer_address = recoverAddressFromSignature(
            nonce,
            transferred_amount,
            locksroot,
            extra_hash,
            signature 
        );
        require(transfer_address == self.closing_address);

        // Update the structure of the closer with its data provided by the
        // counterparty
        closer_index = 1 - caller_index;

        self.participants[closer_index].nonce = nonce;
        self.participants[closer_index].locksroot = locksroot;
        self.participants[closer_index].transferred_amount = transferred_amount;
    }

    function recoverAddressFromSignature(
        uint64 nonce,
        uint256 transferred_amount,
        bytes32 locksroot,
        bytes32 extra_hash,
        bytes signature
    )
        constant
        internal
        returns (address)
    {
        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes32 signed_hash;

        require(signature.length == 65);

        signed_hash = keccak256(
            nonce,
            transferred_amount,
            locksroot,
            this,
            extra_hash
        );

        (r, s, v) = signatureSplit(signature);
        return ecrecover(signed_hash, v, r, s);
    }

    /// @notice Unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param locked_encoded The lock
    /// @param merkle_proof The merkle proof
    /// @param secret The secret
    function withdraw(
        Data storage self,
        bytes locked_encoded,
        bytes merkle_proof,
        bytes32 secret 
    )
        isClosed(self)
        public
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
        require(counterparty.locksroot != 0);

        (expiration, amount, hashlock) = decodeLock(locked_encoded);

        // A lock can be withdrawn only once per participant
        require(!counterparty.withdrawn_locks[hashlock]);

        counterparty.withdrawn_locks[hashlock] = true;

        // The lock must not have expired, it does not matter how far in the
        // future it would have expired
        require(expiration >= block.number);
        require(hashlock == keccak256(secret));

        h = computeMerkleRoot(locked_encoded, merkle_proof);

        require(counterparty.locksroot == h);

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

    /// @notice Settles the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return The participants with netted balances
    function settle(Data storage self)
        isClosed(self)
        timeoutOver(self)
        public
    {
        uint8 closing_index;
        uint8 counter_index;
        uint256 total_deposit;
        uint256 counter_net;
        uint256 closer_amount;
        uint256 counter_amount;

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
            require(self.token.transfer(counter_party.node_address, counter_amount));
        }

        if (closer_amount > 0) {
            require(self.token.transfer(closing_party.node_address, closer_amount));
        }

        selfdestruct(0x00000000000000000000);
    }

    function index_or_throw(Data storage self, address participant_address)
        constant
        private
        returns (uint8)
    {
        uint8 n;
        // Return index of participant, or throw
        n = self.participant_index[participant_address];
        assert(n != 0);
        return n - 1;
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

    function decodeLock(bytes lock)
        pure
        internal
        returns (uint64 expiration, uint amount, bytes32 hashlock)
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

    function computeMerkleRoot(bytes lock, bytes merkle_proof)
        pure
        internal
        returns (bytes32)
    {
        require(merkle_proof.length % 32 == 0);

        uint i;
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

    function min(uint a, uint b) pure internal returns (uint)
    {
        return a > b ? b : a;
    }

    function max(uint a, uint b) pure internal returns (uint)
    {
        return a > b ? a : b;
    }
}
