pragma solidity ^0.4.0;

import "./Token.sol";

library NettingChannelLibrary {
    struct Lock
    {
        uint64 expiration;
        uint amount;
        bytes32 hashlock;
    }

    struct Participant
    {
        address node_address;
        uint256 balance;
        uint256 netted;
        uint256 transferred_amount;
        uint64 nonce;
        bytes32 locksroot;
        Lock[] unlocked;
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
        mapping(bytes32 => bool) locks;
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

    modifier isCounterParty(Data storage self, address caller) {
        if (caller == self.closing_address) {
            throw;
        }
        address participant0 = self.participants[0].node_address;
        address participant1 = self.participants[1].node_address;
        if (caller != participant0 && caller != participant1) {
            throw;
        }
        _;
    }

    modifier inNonceRange(Data storage self, bytes message) {
        uint64 nonce;
        nonce = getNonce(message);
        if (nonce < self.opened * (2 ** 32) || nonce >= (self.opened + 1) * (2 ** 32))
            throw;
        _;
    }

    modifier channelSettled(Data storage self) {
        if (self.settled == 0)
            throw;
        _;
    }

    modifier notYetUpdated(Data storage self) {
        if (self.updated)
            throw;
        _;
    }

    /// @notice Deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param caller_address The address of the invoker of the function
    /// @param channel_address The address of the channel
    /// @param amount The amount to be deposited to the address
    /// @return Success if the transfer was successful
    /// @return The new balance of the invoker
    function deposit(
        Data storage self,
        address caller_address,
        address channel_address,
        uint256 amount)
        returns (bool success, uint256 balance)
    {

        if (self.closed != 0) {
            throw;
        }

        if (self.token.balanceOf(caller_address) < amount) {
            throw;
        }

        uint8 index = index_or_throw(self, caller_address);

        Participant storage participant = self.participants[index];

        success = self.token.transferFrom(
            caller_address,
            channel_address,
            amount
        );

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

    /// @notice Get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return The partner of the calling party
    function partner(Data storage self, address one_address) constant returns (address) {
        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (one_address == node1.node_address) {
            return node2.node_address;
        }

        if (one_address == node2.node_address) {
            return node1.node_address;
        }

        return 0x0;
    }

    function transferredAmount(Data storage self, address participant_address)
        constant
        returns (uint)
    {
         uint8 index = index_or_throw(self, participant_address);
         Participant storage participant = self.participants[index];
         return participant.transferred_amount;
    }

    function addressAndBalance(Data storage self)
        constant
        returns(
        address participant1,
        uint balance1,
        address participant2,
        uint balance2)
    {
        Participant[2] participants = self.participants;
        Participant node1 = participants[0];
        Participant node2 = participants[1];

        // return by name
        participant1 = node1.node_address;
        balance1 = node1.balance;
        participant2 = node2.node_address;
        balance2 = node2.balance;
    }

    /// @notice Close a channel between two parties that was used bidirectionally
    /// @param caller_address The address of the participant closing the channel
    /// @param their_transfer The latest known transfer of the other participant
    ///                       to the channel. Can also be empty, in which case
    ///                       we are attempting to close a channel without any
    ///                       transfers.
    function close(
        Data storage self,
        address caller_address,
        bytes their_transfer)
    {
        uint closer_index;
        uint counterparty_index;
        bytes memory transfer_raw;
        uint64 nonce;
        address transfer_address;

        // Already closed
        if (self.closed > 0) {
            throw;
        }

        // Only a participant can call close
        closer_index = index_or_throw(self, caller_address);

        self.closing_address = caller_address;
        self.closed = block.number;

        // Only the closing party can provide a transfer from the counterparty,
        // and only when this function is called, i.e. this value can not be
        // updated afterwards.

        // An empty value means that the closer never received a transfer, or
        // he is intentionally not providing the latest transfer, in which case
        // the closing party is going to lose the tokens that were transferred
        // to him.
        if (their_transfer.length != 0) {

            // only accept messages with a valid nonce
            nonce = getNonce(their_transfer);
            if (nonce < self.opened * (2 ** 32) || nonce >= (self.opened + 1) * (2 ** 32)) {
                throw;
            }

            (transfer_raw, transfer_address) = getTransferRawAddress(their_transfer);
            counterparty_index = index_or_throw(self, transfer_address);

            // only a message from the counter party is valid
            if (closer_index == counterparty_index) {
                throw;
            }

            // update the structure of the counterparty with its data provided
            // by the closing node
            Participant storage counterparty = self.participants[counterparty_index];
            decodeAndAssign(counterparty, transfer_raw);
        }

    }

    function processTransfer(Data storage self, Participant storage node1, Participant storage node2, bytes transfer)
        inNonceRange(self, transfer)
        internal
        returns (address)
    {
        bytes memory transfer_raw;
        address transfer_address;

        if (transfer.length <= 65) {
            throw;
        }

        (transfer_raw, transfer_address) = getTransferRawAddress(transfer);
        if (node1.node_address == transfer_address) {
            Participant storage sender = node1;
        } else if (node2.node_address == transfer_address) {
            sender = node2;
        } else {
            throw;
        }

        decodeAndAssign(sender, transfer_raw);

        return sender.node_address;
    }

    /// @notice Updates (disputes) the state after closing.
    /// @param caller_address The counterparty to the channel. The participant
    ///                       that did not close the channel.
    /// @param their_transfer The transfer the counterparty believes is the
    ///                        valid state for the first participant.
    function updateTransfer(
        Data storage self,
        address caller_address,
        bytes their_transfer
    )
        notSettledButClosed(self)
        stillTimeout(self)
        isCounterParty(self, caller_address)
        notYetUpdated(self)
    {
        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        processTransfer(self, node1, node2, their_transfer);
        self.updated = true;
    }

    /// @notice Unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param caller_address The calling address
    /// @param locked_encoded The lock
    /// @param merkle_proof The merkle proof
    /// @param secret The secret
    function unlock(
        Data storage self,
        address caller_address,
        bytes locked_encoded,
        bytes merkle_proof,
        bytes32 secret)
        notSettledButClosed(self)
    {
        uint amount;
        uint partner_id;
        uint64 expiration;
        bytes32 el;
        bytes32 h;
        bytes32 hashlock;

        (expiration, amount, hashlock) = decodeLock(locked_encoded);

        if (self.locks[hashlock]) {
            throw;
        }

        if (expiration < block.number) {
            throw;
        }

        if (hashlock != sha3(secret)) {
            throw;
        }

        //Check if caller_address is a participant and select her partner
        uint8 index = 1 - index_or_throw(self, caller_address);

        Participant storage counterparty = self.participants[index];
        if (counterparty.nonce == 0) {
            throw;
        }

        h = computeMerkleRoot(locked_encoded, merkle_proof);

        if (counterparty.locksroot != h) {
            throw;
        }

        counterparty.unlocked.push(Lock(expiration, amount, hashlock));
        self.locks[hashlock] = true;
    }

    function computeMerkleRoot(bytes lock, bytes merkle_proof)
        private
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
    function settle(Data storage self, address caller_address)
        notSettledButClosed(self)
        timeoutOver(self)
    {
        uint total_deposit;
        uint k;

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        node1.netted = node1.balance + node2.transferred_amount - node1.transferred_amount;
        node2.netted = node2.balance + node1.transferred_amount - node2.transferred_amount;

        for (k = 0; k < node1.unlocked.length; k++) {
            node1.netted -= node1.unlocked[k].amount;
            node2.netted += node1.unlocked[k].amount;
        }

        for (k = 0; k < node2.unlocked.length; k++) {
            node2.netted -= node2.unlocked[k].amount;
            node1.netted += node2.unlocked[k].amount;
        }

        self.settled = block.number;
        total_deposit = node1.balance + node2.balance;

        Participant memory closing_party;
        Participant memory other_party;

        if (node1.node_address == self.closing_address) {
            closing_party = node1;
            other_party = node2;
        } else {
            closing_party = node2;
            other_party = node1;
        }

        // first pay out to the party that did not close the channel
        uint amount = total_deposit < other_party.netted
            ? total_deposit
            : other_party.netted;
        if (amount > 0) {
            if (!self.token.transfer(other_party.node_address, amount)) {
                throw;
            }
        }
        // then payout whatever can be paid out to the closing party
        amount = total_deposit - other_party.netted;
        if (amount > 0) {
            if (!self.token.transfer(closing_party.node_address, amount)) {
                throw;
            }
        }

        kill(self);
    }

    function getTransferRawAddress(bytes memory signed_transfer) private returns (bytes memory, address) {
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

    function decodeAndAssign(Participant storage sender, bytes transfer_raw) private {
        // all checks must be done by now
        uint cmdid;

        cmdid = uint(transfer_raw[0]);

        if (cmdid == 5) {
            assignDirectTransfer(sender, transfer_raw);
        } else if (cmdid == 7) {
            assignMediatedTransfer(sender, transfer_raw);
        } else if (cmdid == 8) {
            assignRefundTransfer(sender, transfer_raw);
        } else {
            throw;
        }
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

    // TODO: use sstore instead of these temporaries

    function assignDirectTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 124) { // size of the raw message without the signature
            throw;
        }

        uint64 nonce;
        uint256 transferred_amount;
        bytes32 locksroot;

        assembly {
                                                          // [0:1] cmdid
                                                          // [1:4] pad
            nonce := mload(add(message, 12))              // [4:12] nonce
                                                          // [12:20] identifier
                                                          // [20:40] token
                                                          // [40:60] recipient
            transferred_amount := mload(add(message, 92)) // [60:92] transferred_amount
            locksroot := mload(add(message, 124))         // [92:124] optional_locksroot
        }

        participant.nonce = nonce;
        participant.transferred_amount = transferred_amount;
        participant.locksroot = locksroot;
    }

    function assignMediatedTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 268) { // size of the raw message without the signature
            throw;
        }

        uint64 nonce;
        bytes32 locksroot;
        uint256 transferred_amount;
        uint256 lock_amount;

        assembly {
                                                           // [0:1] cmdid
                                                           // [1:4] pad
            nonce := mload(add(message, 12))               // [4:12] nonce
                                                           // [12:20] identifier
                                                           // [20:28] expiration
                                                           // [28:48] token
                                                           // [48:68] recipient
                                                           // [68:88] target
                                                           // [88:108] initiator
            locksroot := mload(add(message, 140))          // [108:140] locksroot
                                                           // [140:172] hashlock
            transferred_amount := mload(add(message, 204)) // [172:204] transferred_amoun
                                                           // [204:236] amount
                                                           // [236:268] fee
        }

        participant.nonce = nonce;
        participant.locksroot = locksroot;
        participant.transferred_amount = transferred_amount;
    }

    function assignRefundTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 196) { // size of the raw message without the signature
            throw;
        }

        uint64 nonce;
        bytes32 locksroot;
        uint256 transferred_amount;
        uint256 lock_amount;

        assembly {
                                                            // [0:1] cmdid
                                                            // [1:4] pad
            nonce := mload(add(message, 12))                // [4:12] nonce
                                                            // [12:20] identifier
                                                            // [20:28] expiration
                                                            // [28:48] token
                                                            // [48:68] recipient
            locksroot := mload(add(message, 100))           // [68:100] locksroot
            transferred_amount := mload(add(message, 132))  // [100:132] transferred_amount
                                                            // [132:164] amount
                                                            // [164:196] hashlock
        }

        participant.nonce = nonce;
        participant.locksroot = locksroot;
        participant.transferred_amount = transferred_amount;
    }

    function decodeLock(bytes lock) private returns (uint64 expiration, uint amount, bytes32 hashlock) {
        if (lock.length != 72) {
            throw;
        }

        assembly {
            expiration := mload(add(lock, 8))   // [0:8] expiration
            amount := mload(add(lock, 40))      // [8:40] amont
            hashlock := mload(add(lock, 72))    // [40:72] hashlock

        }
    }

    // Get nonce from a message
    function getNonce(bytes message) private returns (uint64 nonce) {
        // don't care about length of message since nonce is always at a fixed position
        assembly {
            nonce := mload(add(message, 12))
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

    function index_or_throw(Data storage self, address caller_address) private returns (uint8) {
        uint8 n;
        // Return index of participant, or throw
        n = self.participant_index[caller_address];
        if (n == 0) {
            throw;
        }
        return n - 1;
    }

    function kill(Data storage self) channelSettled(self) {
        selfdestruct(0x00000000000000000000);
    }
}
