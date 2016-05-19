import "Decoder.sol";
contract NettingContract {
    uint lockedTime;
    address assetAddress;
    uint opened;
    uint closed;
    uint settled;
    address closingAddress;

    struct Transfer
    {
        address sender;
        uint nonce;
        address asset;
        uint balance;
        address recipient;
        bytes32 locksroot;
        bytes32 secret;
        uint expiration;
    }
    struct Unlocked 
    {
        bytes merkleProof;
        bytes32 hashlock;
        bytes32 secret;
        uint amount;
        uint expiration;
    } 
    struct Participant
    {
        address addr;
        uint deposit;
        uint netted;
        uint transferedAmount;
        Transfer lastSentTransfer;
        Unlocked unlocked;
    }
    Participant[2] participants; // We only have two participants at all times

    event ChannelOpened(address assetAdr); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO
    event ChannelSecretRevealed(); //TODO
    
    modifier inParticipants {
        if (msg.sender != participants[0].addr &&
            msg.sender != participants[1].addr) throw;
        _
    }

    function NettingContract(address assetAdr, address participant1, address participant2) {
        opened = 0;
        closed = 0;
        settled = 0;
        assetAddress = assetAdr;
        participants[0].addr = participant1;
        participants[1].addr = participant2;
    }

    // Get the index of an address in participants
    function atIndex(address addr) returns (uint index) {
        if (addr == participants[0].addr) return 0;
        else return 1;
    }


    /// @notice deposit(address, uint) to deposit amount to a participant.
    /// @dev Deposit an amount to a participating address.
    /// @param amount (uint) the amount to be deposited to the address
    function deposit(uint amount) inParticipants {
        if (msg.sender.balance < amount) throw; // TODO check asset contract
        participants[atIndex(msg.sender)].deposit += amount;
        if(isOpen() && opened == 0) open();
    }


    /// @notice open() to set the opened to be the current block and triggers 
    /// the event ChannelOpened()
    /// @dev Sets the value of `opened` to be the value of the current block.
    /// param none
    /// returns none, but changes the value of `opened` and triggers the event ChannelOpened.
    function open() {
        opened = block.number;

        // trigger event
        ChannelOpened(assetAddress);
    }

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return p (address) the partner of the calling party
    function partner(address a) returns (address p) {
        if (a == participants[0].addr) return participants[1].addr;
        else return participants[0].addr;
    }


    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() constant returns (bool open) {
        if (closed == 0) throw;
        if (participants[0].deposit > 0 || participants[1].deposit > 0) return true;
        else return false;
    }


    /// @notice close(bytes, bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    function close(bytes firstEncoded) inParticipants { 
        if (settled > 0) throw; // channel already settled
        if (closed > 0) throw; // channel is closing

        // check if sender of message is a participant
        if (getSender(firstEncoded) != participants[0].addr &&
            getSender(firstEncoded) != participants[1].addr) throw;

        uint partnerId = atIndex(partner(msg.sender));
        uint senderId = atIndex(msg.sender);

        decode(firstEncoded);

        // mark closed
        closed = block.number;
        closingAddress = msg.sender;

        uint amount1 = participants[senderId].transferedAmount;
        uint amount2 = participants[partnerId].transferedAmount;

        uint allowance = participants[senderId].deposit + participants[partnerId].deposit;
        uint difference;
        if(amount1 > amount2) {
            difference = amount1 - amount2;
        } else {
            difference = amount2 - amount1;
        }
        
        // TODO
        // if (difference > allowance) penalize();

        // trigger event
        //TODO
        ChannelClosed();
    }


    /// @notice close(bytes, bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    /// @param secondEncoded (bytes) the last sent transfer of the msg.sender
    function close(bytes firstEncoded, bytes secondEncoded) inParticipants { 
        if (settled > 0) throw; // channel already settled
        if (closed > 0) throw; // channel is closing
        
        // check if the sender of either of the messages is a participant
        if (getSender(firstEncoded) != participants[0].addr &&
            getSender(firstEncoded) != participants[1].addr) throw;
        if (getSender(secondEncoded) != participants[0].addr &&
            getSender(secondEncoded) != participants[1].addr) throw;

        // Don't allow both transfers to be from the same sender
        if (getSender(firstEncoded) == getSender(secondEncoded)) throw;

        uint partnerId = atIndex(partner(msg.sender));
        uint senderId = atIndex(msg.sender);
        
        decode(firstEncoded);
        decode(secondEncoded);

        // mark closed
        closed = block.number;
        closingAddress = msg.sender;

        uint amount1 = participants[senderId].transferedAmount;
        uint amount2 = participants[partnerId].transferedAmount;

        uint allowance = participants[senderId].deposit + participants[partnerId].deposit;
        uint difference;
        if(amount1 > amount2) {
            difference = amount1 - amount2;
        } else {
            difference = amount2 - amount1;
        }
        
        // TODO
        // if (difference > allowance) penalize();

        
        // trigger event
        //TODO
        ChannelClosed();
    }


    /// @notice updateTransfer(bytes) to update last known transfer
    /// @dev Allow the partner to update the last known transfer
    /// @param message (bytes) the encoded transfer message
    function updateTransfer(bytes message) inParticipants {
        if (settled > 0) throw; // channel already settled
        if (closed == 0) throw; // channel is open
        if (msg.sender == closingAddress) throw; // don't allow closer to update
        if (closingAddress == getSender(message)) throw;

        decode(message);

        // TODO check if tampered and penalize
        // TODO check if outdated and penalize

    }


    /// @notice unlock(bytes, bytes, bytes32) to unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param lockedEncoded (bytes) the lock
    /// @param merkleProof (bytes) the merkle proof
    /// @param secret (bytes32) the secret
    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) inParticipants{
        if (settled > 0) throw; // channel already settled
        if (closed == 0) throw; // channel is open

        uint partnerId = atIndex(partner(msg.sender));
        uint senderId = atIndex(msg.sender);

        if (participants[partnerId].lastSentTransfer.nonce == 0) throw;

        bytes32 h = sha3(lockedEncoded);

        for (uint i = 0; i < merkleProof.length; i += 64) {
            bytes32 left;
            left = bytesToBytes32(slice(merkleProof, i, i + 32), left);
            bytes32 right;
            right = bytesToBytes32(slice(merkleProof, i + 32, i + 64), right);
            if (h != left && h != right) throw;
            h = sha3(left, right);
        }

        if (participants[partnerId].lastSentTransfer.locksroot != h) throw;

        // TODO decode lockedEncoded into a Unlocked struct and append
        
        //participants[partnerId].unlocked.push(lock);
    }
    function bytesToBytes32(bytes b, bytes32 i) returns (bytes32 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }

    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[]) the participants with netted balances
    /*
    function settle() returns (Participant[] participants) {
        if (settled > 0) throw;
        if (closed == 0) throw;
        if (closed + lockedTime > block.number) throw; //if locked time has expired throw

        for (uint i = 0; i < participants.length; i++) {
            uint otherIdx = atIndex(partner(participants[i].addr)); 
            participants[i].netted = participants[i].deposit;
            if (participants[i].lastSentTransfer != 0) {
                participants[i].netted = participants[i].lastSentTransfer.balance;
            }
            if (participants[otherIdx].lastSentTransfer != 0) {
                participants[i].netted = participants[otherIdx].lastSentTransfer.balance;
            }
        }

        //for (uint j = 0; j < participants.length; j++) {
            //uint otherIdx = atIndex(partner(participants[j].addr)); 
        //}

        // trigger event
        //ChannelSettled();
    }
    */

    // Get the nonce of the last sent transfer
    function getNonce(bytes message) returns (uint8 non) {
        // Direct Transfer
        if (message[0] == 5) {
            (non, , , , , , ) = Decoder.decodeTransfer(message);
        }
        // Locked Transfer
        if (message[0] == 6) {
            (non, , , ) = Decoder.decodeLockedTransfer1(message);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            (non, , , , ) = Decoder.decodeMediatedTransfer1(message); 
        }
        // Cancel Transfer
        if (message[0] == 8) {
            (non, , , ) = Decoder.decodeCancelTransfer1(message);
        }
        else throw;
    }

    // Gets the sender of a last sent transfer
    function getSender(bytes message) returns (address sndr) {
        // Secret
        bytes sig;
        bytes32 h;
        bytes32 sec;
        uint8 non;
        address ass;
        address rec;
        uint bal;
        bytes32 olo;
        uint amo;
        bytes32 has;
        bytes32 loc;
        bytes32 lock;
        uint8 exp;
        address tar;
        address ini;
        uint fee;
        if (message[0] == 4) {
            (sec, sig) = Decoder.decodeSecret(message);
            h = sha3(sec);
            sndr = ecrecovery(h, sig);
        }
        // Direct Transfer
        if (message[0] == 5) {
            (non, ass, rec, bal, olo, , sig) = Decoder.decodeTransfer(message);
            h = sha3(non, ass, bal, rec, olo); //need the optionalLocksroot
            sndr = ecrecovery(h, sig);
        }
        // Locked Transfer
        if (message[0] == 6) {
            (non, exp, ass, rec) = Decoder.decodeLockedTransfer1(message);
            (loc, bal, amo, has, sig) = Decoder.decodeLockedTransfer2(message);
            h = sha3(non, ass, bal, rec, loc, lock); //need the lock
            sndr = ecrecovery(h, sig);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            (non, exp, ass, rec, tar) = Decoder.decodeMediatedTransfer1(message); 
            (ini, loc, , , , fee, sig) = Decoder.decodeMediatedTransfer2(message);
            h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
            sndr = ecrecovery(h, sig);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            (non, , ass, rec) = Decoder.decodeCancelTransfer1(message);
            (loc, bal, , , sig) = Decoder.decodeCancelTransfer2(message);
            h = sha3(non, ass, bal, rec, loc, lock); //need the lock
            sndr = ecrecovery(h, sig);
        }
        else throw;
    }

    function decode(bytes message) {
        // Secret
        bytes sig;
        bytes32 h;
        bytes32 sec;
        uint8 non;
        address ass;
        address rec;
        uint bal;
        bytes32 olo;
        uint amo;
        bytes32 has;
        bytes32 loc;
        bytes32 lock;
        uint8 exp;
        address tar;
        address ini;
        uint fee;
        bytes32 h;
        uint i;
        if (message[0] == 4) {
            (sec, sig) = Decoder.decodeSecret(message);
            participants[atIndex(msg.sender)].lastSentTransfer.secret = sec;
            h = sha3(sec);
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Direct Transfer
        if (message[0] == 5) {
            (non, ass, rec, bal, loc, sec, sig) = Decoder.decodeTransfer(message);
            i = atIndex(msg.sender); // should be sender of message
            participants[i].lastSentTransfer.nonce = non;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.balance = bal;
            h = sha3(non, ass, bal, rec, loc);
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Locked Transfer
        if (message[0] == 6) {
            (non, exp, ass, rec) = Decoder.decodeLockedTransfer1(message);
            (loc, bal, amo, has, sig) = Decoder.decodeLockedTransfer2(message);
            i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].lastSentTransfer.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            (non, exp, ass, rec, tar) = Decoder.decodeMediatedTransfer1(message); 
            (ini, loc, has, bal, amo, fee, sig) = Decoder.decodeMediatedTransfer2(message);
            i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].unlocked.hashlock = has;
            participants[i].lastSentTransfer.balance = bal;
            // amount not needed?
            h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            (non, exp, ass, rec) = Decoder.decodeCancelTransfer1(message);
            (loc, bal, amo, has, sig) = Decoder.decodeCancelTransfer2(message);
            i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].lastSentTransfer.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            h = sha3(non, ass, bal, rec, loc, lock); //need the lock
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        else throw;
    }

    // Written by Alex Beregszaszi (@axic), use it under the terms of the MIT license.
    function ecrecovery(bytes32 hash, bytes sig) returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        
        // FIXME: Should this throw, or return 0?
        if (sig.length != 65)
          return 0;

        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(sig, 65)), 1)
        }
        
        // old geth sends a `v` value of [0,1], while the new, in line with the YP sends [27,28]
        if (v < 27)
          v += 27;
        
        return ecrecover(hash, v, r, s);
    }

    function ecverify(bytes32 hash, bytes sig, address signer) returns (bool) {
        return ecrecovery(hash, sig) == signer;
    }

    function slice(bytes a, uint start, uint end) returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        if (start > end) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    // empty function to handle wrong calls
    function () { throw; }
}
