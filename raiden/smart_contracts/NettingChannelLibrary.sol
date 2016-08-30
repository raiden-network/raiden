import "Token.sol";

library NettingChannelLibrary {
    struct Lock
    {
        uint64 expiration;
        uint amount;
        bytes32 hashlock;
    }

    struct Participant
    {
        address nodeAddress;
        uint256 balance;
        uint256 netted;
        uint256 transferedAmount;
        uint256 amount;
        bytes merkleProof;
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
        uint settleTimeout;
        uint opened;
        uint closed;
        uint settled;
        address closingAddress;
        Token token;
        Participant[2] participants;
    }

    modifier notSettledButClosed(Data storage self) {
        if (self.settled > 0 || self.closed == 0)
            throw;
        _
    }

    modifier stillTimeout(Data storage self) {
        if (self.closed + self.settleTimeout < block.number)
            throw;
        _
    }

    modifier timeoutOver(Data storage self) {
        if (self.closed + self.settleTimeout > block.number)
            throw;
        _
    }

    /// @notice deposit(uint) to deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param callerAddress (address) the address of the invoker of the function
    /// @param channelAddress (address) the address of the channel
    /// @param amount (uint) the amount to be deposited to the address
    /// @return success (bool) if the transfer was successful
    /// @return balance (uint256) the new balance of the invoker
    function deposit(Data storage self, address callerAddress, address channelAddress, uint256 amount) returns (bool success, uint256 balance) {
        uint index;

        if (self.closed != 0) {
            throw;
        }

        if (self.token.balanceOf(callerAddress) < amount) {
            throw;
        }

        Participant storage participant = self.participants[0];
        if (participant.nodeAddress != callerAddress) {
            participant = self.participants[1];
            if (participant.nodeAddress != callerAddress) {
                throw;
            }
        }

        success = self.token.transferFrom(
            callerAddress,
            channelAddress,
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
    /// @return partnerAddress (address) the partner of the calling party
    function partner(Data storage self, address one_address) constant returns (address) {
        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (one_address == node1.nodeAddress) {
            return node2.nodeAddress;
        }

        if (one_address == node2.nodeAddress) {
            return node1.nodeAddress;
        }

        return 0x0;
    }

    function addressAndBalance(Data storage self) constant returns (address participant1, uint balance1, address participant2, uint balance2) {
        Participant[2] participants = self.participants;
        Participant node1 = participants[0];
        Participant node2 = participants[1];

        // return by name
        participant1 = node1.nodeAddress;
        balance1 = node1.balance;
        participant2 = node2.nodeAddress;
        balance2 = node2.balance;
    }

    function closeSingleTransfer(Data storage self, address callerAddress, bytes signed_transfer) {
        bytes memory transfer_raw;
        address transfer_address;

        if (self.settled > 0 || self.closed > 0) {
            throw;
        }

        if (signed_transfer.length <= 65) {
            throw;
        }

        (transfer_raw, transfer_address) = getTransferRawAddress(signed_transfer);

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (callerAddress != node1.nodeAddress && callerAddress != node2.nodeAddress) {
            throw;
        }

        if (node1.nodeAddress == transfer_address) {
            Participant storage sender = node1;
        } else if (node2.nodeAddress == transfer_address) {
            sender = node2;
        } else {
            throw;
        }

        decode_and_assign(sender, transfer_raw);

        self.closingAddress = callerAddress;
        self.closed = block.number;
    }

    /// @notice close(bytes, bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    /// @param secondEncoded (bytes) the last sent transfer of the msg.sender
    function close(Data storage self, address callerAddress, bytes firstEncoded, bytes secondEncoded) {
        bytes memory first_raw;
        bytes memory second_raw;
        address first_address;
        address second_address;
        bytes32 transfer_sender;

        if (self.settled > 0 || self.closed > 0) {
            throw;
        }

        if (firstEncoded.length <= 65 || secondEncoded.length <= 65) {
            throw;
        }

        (first_raw, first_address) = getTransferRawAddress(firstEncoded);
        (second_raw, second_address) = getTransferRawAddress(secondEncoded);

        if (first_address == second_address) {
            throw;
        }

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (callerAddress != node1.nodeAddress && callerAddress != node2.nodeAddress) {
            throw;
        }

        if (node1.nodeAddress == first_address) {
            Participant storage first_sender = node1;
        } else if (node2.nodeAddress == first_address) {
            first_sender = node2;
        } else {
            throw;
        }

        if (node1.nodeAddress == second_address) {
            Participant storage second_sender = node1;
        } else if (node2.nodeAddress == second_address) {
            second_sender = node2;
        } else {
            throw;
        }

        decode_and_assign(first_sender, first_raw);
        decode_and_assign(second_sender, second_raw);

        self.closingAddress = callerAddress;
        self.closed = block.number;
    }

    /// @notice updateTransfer(bytes) to update last known transfer
    /// @dev Allow the partner to update the last known transfer
    function updateTransfer(Data storage self, address callerAddress, bytes signed_transfer)
        notSettledButClosed(self)
        stillTimeout(self)
    {
        uint64 nonce;
        bytes memory transfer_raw;
        address transfer_address;

        (transfer_raw, transfer_address) = getTransferRawAddress(signed_transfer);

        // participant that called close cannot update
        if (self.closingAddress == transfer_address) {
            throw;
        }

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        if (node1.nodeAddress == transfer_address) {
            Participant storage sender = node1;
        } else if (node2.nodeAddress == transfer_address) {
            sender = node2;
        } else {
            throw;
        }

        assembly {
            nonce := mload(add(transfer_raw, 12))  // skip cmdid and padding
        }

        if (nonce < sender.nonce) {
            throw;
        }

        decode_and_assign(sender, transfer_raw);

        // TODO check if tampered and penalize
        // TODO check if outdated and penalize
    }

    /// @notice unlock(bytes, bytes, bytes32) to unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param lockedEncoded (bytes) the lock
    /// @param merkleProof (bytes) the merkle proof
    /// @param secret (bytes32) the secret
    function unlock(
        Data storage self,
        address callerAddress,
        bytes lockedEncoded,
        bytes merkleProof,
        bytes32 secret)
        notSettledButClosed(self)
    {
        uint partnerId;
        uint64 expiration;
        uint amount;
        bytes32 hashlock;
        bytes32 h;
        bytes32 el;

        (expiration, amount, hashlock) = decodeLock(lockedEncoded);

        if (expiration < block.number)
            throw;

        if (hashlock != sha3(secret))
            throw;

        Participant[2] storage participants = self.participants;
        Participant storage participant = participants[0];
        if (participant.nodeAddress != callerAddress) {
            participant = participants[1];
            if (participant.nodeAddress != callerAddress) {
                throw;
            }
        }

        if (participant.nonce == 0) {
            throw;
        }

        h = sha3(lockedEncoded);
        for (uint i = 32; i <= merkleProof.length; i += 32) {
            assembly {
                el := mload(add(merkleProof, i))
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
    function settle(Data storage self, address callerAddress)
        notSettledButClosed(self)
        timeoutOver(self)
    {
        uint totalNetted;
        uint totalDeposit;
        uint k;

        Participant[2] storage participants = self.participants;
        Participant storage node1 = participants[0];
        Participant storage node2 = participants[1];

        node1.netted = node1.balance + node2.transferedAmount - node1.transferedAmount;
        node2.netted = node2.balance + node1.transferedAmount - node2.transferedAmount;

        for (k=0; k < node1.unlocked.length; k++) {
            node1.netted += node1.unlocked[k].amount;
            node2.netted -= node1.unlocked[k].amount;
        }

        for (k=0; k < node2.unlocked.length; k++) {
            node2.netted += node2.unlocked[k].amount;
            node1.netted -= node2.unlocked[k].amount;
        }

        self.settled = block.number;

        totalNetted = node1.netted + node2.netted;
        totalDeposit = node1.balance + node2.balance;

        if (totalNetted != totalDeposit) {
            throw;
        }

        self.token.transfer(node1.nodeAddress, node1.netted);
        self.token.transfer(node2.nodeAddress, node2.netted);
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
        var (r, s, v) = signature_split(signature);
        transfer_address = ecrecover(transfer_hash, v, r, s);

        return (transfer_raw, transfer_address);
    }

    function decode_and_assign(Participant storage sender, bytes transfer_raw) private {
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

    // notes:
    // about the length of variable types:
    //  - inside an assembly block a type of `bytes memory` works as a pointer to
    //  memory, since bytes is variable size it follows the ethereum contract
    //  abi.
    //  - all variable length types start with a size-prefix of type uint256, so
    //  the 256bits/32bytes represent the length of the object.
    //  - the variable start pointing in the last byte of the length
    // - pointer arithmetic works on a byte basis, to `add(var, 1)` will advance
    // 1 byte.
    // - the pointer should be at the _last_ byte of the value, mload loads
    // values from higher-to-lower addresses

    // TODO: use sstore instead of these temporaries

    function assignDirectTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 148) {  // raw message size (without signature)
            throw;
        }

        uint64 nonce;
        address asset;
        address recipient;
        uint256 transferedAmount;
        bytes32 locksroot;
        bytes32 secret;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))            // nonce [4:12]
            asset := mload(add(message, 32))            // asset [12:32]
            recipient := mload(add(message, 52))        // recipient [32:52]
            transferedAmount := mload(add(message, 84)) // transfered_amount [52:84]
            locksroot := mload(add(message, 116))       // optional_locksroot [84:116]
            secret := mload(add(message, 148))          // optional_secret [116:148]
        }

        participant.nonce = nonce;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.transferedAmount = transferedAmount;
        participant.locksroot = locksroot;
        participant.secret = secret;
    }

    function assignMediatedTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 260) {
            throw;
        }

        uint64 nonce;
        uint64 expiration;
        address asset;
        address recipient;
        bytes32 locksroot;
        bytes32 hashlock;
        uint256 transferedAmount;
        uint256 lockAmount;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))        // nonce [4:12]
            expiration := mload(add(message, 20))   // expiration [12:20]
            asset := mload(add(message, 40))        // asset [20:40]
            recipient := mload(add(message, 60))    // recipient [40:60]
            // target [60:80]
            // initiator [80:100]
            locksroot := mload(add(message, 132))   // locksroot [100:132]
            hashlock := mload(add(message, 164))    // hashlock [100:164]
            transferedAmount := mload(add(message, 196)) // transfered_amount[164:196]
            lockAmount := mload(add(message, 228))  // amount [196:228]
            // fee := mload(add(message, 260))      // fee [228:260]
        }

        participant.nonce = nonce;
        participant.expiration = expiration;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.locksroot = locksroot;
        participant.hashlock = hashlock;
        participant.transferedAmount = transferedAmount;
        participant.amount = lockAmount;
    }

    function assignRefundTransfer(Participant storage participant, bytes memory message) private {
        if (message.length != 188) {
            throw;
        }

        uint64 nonce;
        uint64 expiration;
        address asset;
        address recipient;
        bytes32 locksroot;
        uint256 transferedAmount;
        uint256 lockAmount;
        bytes32 hashlock;

        assembly {
            // cmdid [0:1]
            // pad [1:4]
            nonce := mload(add(message, 12))        // nonce [4:12]
            expiration := mload(add(message, 20))   // expiration [12:20]
            asset := mload(add(message, 40))        // asset [20:40]
            recipient := mload(add(message, 60))    // recipient [40:60]
            locksroot := mload(add(message, 92))    // locksroot [60:92]
            transferedAmount := mload(add(message, 124)) // transfered_amount [92:124]
            lockAmount := mload(add(message, 156))  // amount [124:156]
            hashlock := mload(add(message, 188))    // hashlock [156:188]
        }

        participant.nonce = nonce;
        participant.expiration = expiration;
        participant.asset = asset;
        participant.recipient = recipient;
        participant.locksroot = locksroot;
        participant.transferedAmount = transferedAmount;
        participant.amount = lockAmount;
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

    function signature_split(bytes signature) private returns (bytes32 r, bytes32 s, uint8 v) {
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
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    function () { throw; }
}
