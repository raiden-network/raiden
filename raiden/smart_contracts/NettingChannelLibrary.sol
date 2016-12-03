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
        uint256 amount;
        bytes merkle_proof;
        bytes32 hashlock;
        bytes32 secret;
        uint256 expiration;
        uint64 nonce;
        address asset;
        address recipient;
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

    modifier notClosingAddress(Data storage self, address caller_address) {
        if (caller_address == self.closing_address)
            throw;
        _;
    }

    modifier inNonceRange(Data storage self, bytes message) {
        uint64 nonce;
        nonce = getNonce(message);
        if (nonce < self.opened * (2 ** 32) || nonce >= (self.opened + 1) * (2 ** 32))
            throw;
        _;
    }

    modifier ChannelSettled(Data storage self) {
        if (self.settled == 0) throw;
        _;
    }

    /// @notice deposit(uint) to deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param caller_address (address) the address of the invoker of the function
    /// @param channel_address (address) the address of the channel
    /// @param amount (uint) the amount to be deposited to the address
    /// @return success (bool) if the transfer was successful
    /// @return balance (uint256) the new balance of the invoker
    function deposit(
        Data storage self,
        address caller_address,
        address channel_address,
        uint256 amount)
        returns (bool success, uint256 balance)
    {
        uint index;

        if (self.closed != 0) {
            throw;
        }

        if (self.token.balanceOf(caller_address) < amount) {
            throw;
        }

        Participant storage participant = self.participants[0];
        if (participant.node_address != caller_address) {
            participant = self.participants[1];
            if (participant.node_address != caller_address) {
                throw;
            }
        }

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

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return (address) the partner of the calling party
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

    function closeSingleTransfer(Data storage self, address caller_address, bytes signed_transfer)
        inNonceRange(self, signed_transfer)
    {
        bytes memory transfer_raw;
        address transfer_address;

        if (self.settled > 0 || self.closed > 0) {
            throw;
        }

        if (signed_transfer.length <= 65) {
            throw;
        }

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (caller_address != node1.node_address && caller_address != node2.node_address) {
            throw;
        }

        (transfer_raw, transfer_address) = getTransferRawAddress(signed_transfer);

        if (node1.node_address == transfer_address) {
            Participant storage sender = node1;
        } else if (node2.node_address == transfer_address) {
            sender = node2;
        } else {
            throw;
        }

        decodeAndAssign(sender, transfer_raw);

        self.closing_address = caller_address;
        self.closed = block.number;
    }

    /// @notice close(bytes, bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param first_encoded (bytes) the last sent transfer of the msg.sender
    /// @param second_encoded (bytes) the last sent transfer of the msg.sender
    function close(
        Data storage self,
        address caller_address,
        bytes first_encoded,
        bytes second_encoded)
    {
        uint64 nonce;
        nonce = getNonce(first_encoded);
        // check if nonce is valid. 
        // TODO should be in modifier, but "Stack too deep" error
        if (nonce < self.opened * (2 ** 32) || nonce >= (self.opened + 1) * (2 ** 32))
            throw;
        nonce = getNonce(second_encoded);
        if (nonce < self.opened * (2**32) || nonce >= (self.opened + 1) * (2 ** 32))
            throw;

        bytes memory first_raw;
        bytes memory second_raw;
        address first_address;
        address second_address;
        bytes32 transfer_sender;

        if (self.settled > 0 || self.closed > 0) {
            throw;
        }

        if (first_encoded.length <= 65 || second_encoded.length <= 65) {
            throw;
        }

        (first_raw, first_address) = getTransferRawAddress(first_encoded);
        (second_raw, second_address) = getTransferRawAddress(second_encoded);

        if (first_address == second_address) {
            throw;
        }

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (caller_address != node1.node_address && caller_address != node2.node_address) {
            throw;
        }

        if (node1.node_address == first_address) {
            Participant storage first_sender = node1;
        } else if (node2.node_address == first_address) {
            first_sender = node2;
        } else {
            throw;
        }

        if (node1.node_address == second_address) {
            Participant storage second_sender = node1;
        } else if (node2.node_address == second_address) {
            second_sender = node2;
        } else {
            throw;
        }

        decodeAndAssign(first_sender, first_raw);
        decodeAndAssign(second_sender, second_raw);

        self.closing_address = caller_address;
        self.closed = block.number;
    }

    /// @notice updateTransfer(bytes) to update last known transfer
    /// @dev Allow the partner to update the last known transfer
    function updateTransfer(Data storage self, address caller_address, bytes signed_transfer)
        notSettledButClosed(self)
        stillTimeout(self)
        notClosingAddress(self, caller_address)
    {
        uint64 nonce;
        bytes memory transfer_raw;
        address transfer_address;

        nonce = getNonce(signed_transfer);
        if (nonce < self.opened * (2 ** 32) || nonce >= (self.opened + 1) * (2 ** 32))
            throw;

        (transfer_raw, transfer_address) = getTransferRawAddress(signed_transfer);

        // transfer address must be from counter party
        if (self.closing_address != transfer_address) {
            throw;
        }

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (node1.node_address == transfer_address) {
            Participant storage sender = node1;
        } else if (node2.node_address == transfer_address) {
            sender = node2;
        } else {
            throw;
        }

        if (nonce < sender.nonce || nonce == sender.nonce) {
            throw;
        }

        decodeAndAssign(sender, transfer_raw);

        // TODO check if tampered and penalize
        // TODO check if outdated and penalize
    }

    /// @notice unlock(bytes, bytes, bytes32) to unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param locked_encoded (bytes) the lock
    /// @param merkle_proof (bytes) the merkle proof
    /// @param secret (bytes32) the secret
    function unlock(
        Data storage self,
        address caller_address,
        bytes locked_encoded,
        bytes merkle_proof,
        bytes32 secret)
        notSettledButClosed(self)
    {
        uint partner_id;
        uint64 expiration;
        uint amount;
        bytes32 hashlock;
        bytes32 h;
        bytes32 el;

        (expiration, amount, hashlock) = decodeLock(locked_encoded);

        if (expiration < block.number)
            throw;

        if (hashlock != sha3(secret))
            throw;

        Participant[2] storage participants = self.participants;
        Participant storage participant = participants[0];
        if (participant.node_address != caller_address) {
            participant = participants[1];
            if (participant.node_address != caller_address) {
                throw;
            }
        }

        if (participant.nonce == 0) {
            throw;
        }

        h = sha3(locked_encoded);
        for (uint i = 32; i <= merkle_proof.length; i += 32) {
            assembly {
                el := mload(add(merkle_proof, i))
            }

            if (h < el) {
                h = sha3(h, el);
            } else {
                h = sha3(el, h);
            }
        }

        if (participant.locksroot != h)
            throw;

        participant.unlocked.push(Lock(expiration, amount, hashlock));
    }

    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[2]) the participants with netted balances
    function settle(Data storage self, address caller_address)
        notSettledButClosed(self)
        timeoutOver(self)
    {
        uint total_netted;
        uint total_deposit;
        uint k;

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        node1.netted = node1.balance + node2.transferred_amount - node1.transferred_amount;
        node2.netted = node2.balance + node1.transferred_amount - node2.transferred_amount;

        for (k = 0; k < node1.unlocked.length; k++) {
            node1.netted += node1.unlocked[k].amount;
            node2.netted -= node1.unlocked[k].amount;
        }

        for (k = 0; k < node2.unlocked.length; k++) {
            node2.netted += node2.unlocked[k].amount;
            node1.netted -= node2.unlocked[k].amount;
        }

        self.settled = block.number;

        total_netted = node1.netted + node2.netted;
        total_deposit = node1.balance + node2.balance;

        if (total_netted != total_deposit) {
            throw;
        }

        if (!self.token.transfer(node1.node_address, node1.netted)) throw;
        if (!self.token.transfer(node2.node_address, node2.netted)) throw;

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

    // NOTES about the length of variable types:
    // - variable length types start with a size-prefix of 32bytes (uint256)
    // - bytes is a variable length type
    // - a variable with a bytes type will contain the address of the first data element
    // - solidity starts indexing at 0 (so the 32th byte is at the offset 31)
    //  ref: https://github.com/ethereum/wiki/wiki/Ethereum-Contract-ABI

    // TODO: use sstore instead of these temporaries

    function assignDirectTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 156) {  // raw message size (without signature)
            throw;
        }

        uint64 nonce;
        address asset;
        address recipient;
        uint256 transferred_amount;
        bytes32 locksroot;
        bytes32 secret;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))              // nonce [4:12]
            // identifier [12:20]
            asset := mload(add(message, 40))              // asset [20:40]
            recipient := mload(add(message, 60))          // recipient [40:60]
            transferred_amount := mload(add(message, 92)) // transferred_amount [60:92]
            locksroot := mload(add(message, 124))         // optional_locksroot [92:124]
            secret := mload(add(message, 156))            // optional_secret [124:156]
        }

        participant.nonce = nonce;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.transferred_amount = transferred_amount;
        participant.locksroot = locksroot;
        participant.secret = secret;
    }

    function assignMediatedTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 268) {
            throw;
        }

        uint64 nonce;
        uint64 expiration;
        address asset;
        address recipient;
        bytes32 locksroot;
        bytes32 hashlock;
        uint256 transferred_amount;
        uint256 lock_amount;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))               // nonce [4:12]
            // identifier [12:20]
            expiration := mload(add(message, 28))          // expiration [20:28]
            asset := mload(add(message, 48))               // asset [28:48]
            recipient := mload(add(message, 68))           // recipient [48:68]
            // target [68:88]
            // initiator [88:108]
            locksroot := mload(add(message, 140))          // locksroot [108:140]
            hashlock := mload(add(message, 172))           // hashlock [140:172]
            transferred_amount := mload(add(message, 204)) // transferred_amount[172:204]
            lock_amount := mload(add(message, 236))        // amount [204:236]
            // fee := mload(add(message, 268))             // fee [236:268]
        }

        participant.nonce = nonce;
        participant.expiration = expiration;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.locksroot = locksroot;
        participant.hashlock = hashlock;
        participant.transferred_amount = transferred_amount;
        participant.amount = lock_amount;
    }

    function assignRefundTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 196) {
            throw;
        }

        uint64 nonce;
        uint64 expiration;
        address asset;
        address recipient;
        bytes32 locksroot;
        uint256 transferred_amount;
        uint256 lock_amount;
        bytes32 hashlock;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))                // nonce [4:12]
            // identifier [12:20]
            expiration := mload(add(message, 28))           // expiration [20:28]
            asset := mload(add(message, 48))                // asset [28:48]
            recipient := mload(add(message, 68))            // recipient [48:68]
            locksroot := mload(add(message, 100))           // locksroot [68:100]
            transferred_amount := mload(add(message, 132))  // transferred_amount [100:132]
            lock_amount := mload(add(message, 164))         // amount [132:164]
            hashlock := mload(add(message, 196))            // hashlock [164:196]
        }

        participant.nonce = nonce;
        participant.expiration = expiration;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.locksroot = locksroot;
        participant.transferred_amount = transferred_amount;
        participant.amount = lock_amount;
        participant.hashlock = hashlock;
    }

    function decodeLock(bytes lock) private returns (uint64 expiration, uint amount, bytes32 hashlock) {
        if (lock.length != 72) {
            throw;
        }

        assembly {
            expiration := mload(add(lock, 8))   // expiration [0:8]
            amount := mload(add(lock, 40))      // expiration [8:40]
            hashlock := mload(add(lock, 72))    // expiration [40:72]

        }
    }

    function getNonce(bytes message) private returns (uint64 nonce) {
        // dont care about the length of message since nonce is always in fixed position
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

        n = new bytes(end-start);
        for (uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    function kill(Data storage self) ChannelSettled(self) {
        selfdestruct(0x00000000000000000000);
    }
}
