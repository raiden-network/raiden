contract NettingContract {
    uint lockedTime;
    address assetAddress;
    uint opened;
    uint closed;
    uint settled;
    /*uint settlementTimeout; //maybe not?*/

    struct Transfer
    {
        address sender;
        uint nonce;
        address asset;
        uint balance;
        address recipient;
        bytes32 locksroot;
        bytes32 secret;
    }
    struct Unlocked 
    {
        // Depending on the encoded format
        bytes32 merkleProof;
        bytes32 hashlock;
        bytes32 secret;
        uint amount;
    } 
    struct Participant
    {
        address addr;
        uint deposit;
        uint netted;
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

    function NettingContract(address assetAdr) {
        opened = 0;
        closed = 0;
        settled = 0;
        assetAddress = assetAdr;
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


    /// @notice close(Transfer, unlocked[]) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param lsts (Transfer[]) the last sent transfer of the msg.sender
    /// @param unlckd (Unlocked) the struct containing locked data (a bit uncertain about this)
    function close(bytes[2] lsts, bytes unlckd) inParticipants { 
        // TODO figure out how to get a list of two transfers as argument

        // Update valid claims
        for(uint i = 0; i < lsts.length; i++ ) {
            if (getSender(lsts[i]) != participants[0].addr &&
                getSender(lsts[i]) != participants[1].addr) throw;
            
            uint sndrIdx = atIndex(getSender(lsts[i]));
            if (participants[sndrIdx].lastSentTransfer == 0 || // how to check that for no data
                participants[sndrIdx].lastSentTransfer.nonce < getNonce(lsts[i])){
                decode(lsts);
            }
        }
        
        // Difficult stuff. Not entirely sure about this
        // TODO
        // Register un-locked
        partnerId = atIndex(partner(msg.sender));
        
        // mark closed
        if (closed == 0) closed = block.number;

        // trigger event
        //TODO
        ChannelClosed();
    }


    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[]) the participants with netted balances
    function settle() returns (Participant[] participants) {
        if (settled > 0) throw;
        if (closed == 0) throw;
        if (closed + lockedTime > block.number) throw;

        for (uint i = 0; i < participants.length; i++) {
            uint otherIdx = getIndex(partner(participants[i].addr)); 
            participants[i].netted = participants[i].deposit;
            if (participants[i].lastSentTransfer != 0) {
                participants[i].netted = participants[i].lastSentTransfer.balance;
            }
            if (participants[otherIdx].lastSentTransfer != 0) {
                participants[i].netted = participants[otherIdx].lastSentTransfer.balance;
            }
        }

        for (uint i = 0; i < participants.length; i++) {
            uint otherIdx = getIndex(partner(participants[i].addr)); 
        }

        // trigger event
        /*ChannelSettled();*/
    //}

    // Get the nonce of the last sent transfer
    function getNonce(bytes message) returns (uint8 non) {
        // Direct Transfer
        if (message[0] == 5) {
            (non, , , , , , ) = decodeTransfer(message);
        }
        // Locked Transfer
        if (message[0] == 6) {
            (non, , , ) = decodeLockedTransfer1(message);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            (non, , , , ) = decodeMediatedTransfer1(message); 
        }
        // Cancel Transfer
        if (message[0] == 8) {
            (non, , , ) = decodeCancelTransfer1(message);
        }
        else throw;
    }

    // Gets the sender of a last sent transfer
    function getSender(bytes message) returns (address sndr) {
        // Secret
        if (message[0] == 4) {
            var(sec, sig) = decodeSecret(message);
            bytes32 h = sha3(sec);
            sndr = ecrecovery(h, sig);
        }
        // Direct Transfer
        if (message[0] == 5) {
            var(non, ass, rec, bal, olo, , sig) = decodeTransfer(message);
            bytes32 h = sha3(non, ass, bal, rec, olo); //need the optionalLocksroot
            sndr = ecrecovery(h, sig);
        }
        // Locked Transfer
        if (message[0] == 6) {
            var(non, exp, ass, rec) = decodeLockedTransfer1(message);
            var(loc, bal, amo, has, sig) = decodeLockedTransfer2(message);
            bytes32 h = sha3(non, ass, bal, rec, loc, lock ); //need the lock
            sndr = ecrecovery(h, sig);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            var(non, exp, ass, rec, tar) = decodeMediatedTransfer1(message); 
            var(ini, loc, , , , fee, sig) = decodeMediatedTransfer2(message);
            bytes32 h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
            sndr = ecrecovery(h, sig);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            var(non, , ass, rec) = decodeCancelTransfer1(message);
            var(loc, bal, , , sig) = decodeCancelTransfer2(message);
            bytes32 h = sha3(non, ass, bal, rec, loc, lock); //need the lock
            sndr = ecrecovery(h, sig);
        }
        else throw;
    }

    function decode(bytes message) {
        // Secret
        if (message[0] == 4) {
            var(sec, sig) = decodeSecret(message);
            participants[atIndex(msg.sender)].lastSentTransfer.secret = sec;
            bytes32 h = sha3(sec);
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Direct Transfer
        if (message[0] == 5) {
            var(non, ass, rec, bal, loc, sec, sig) = decodeTransfer(message);
            uint i = atIndex(msg.sender); // should be sender of message
            participants[i].lastSentTransfer.nonce = non;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.balance = bal;
            bytes32 h = sha3(non, add, bal, rec, loc);
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Locked Transfer
        if (message[0] == 6) {
            var(non, exp, ass, rec) = decodeLockedTransfer1(message);
            var(loc, bal, amo, has, sig) = decodeLockedTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].lastSentTransfer.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            bytes32 h = sha3(non, add, bal, rec, loc, lock, tar, ini, fee); //need the lock
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            var(non, exp, ass, rec, tar) = decodeMediatedTransfer1(message); 
            var(ini, loc, has, bal, amo, fee, sig) = decodeMediatedTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].unlocked.hashlock = has;
            participants[i].lastSentTransfer.balance = bal;
            // amount not needed?
            bytes32 h = sha3(non, add, bal, rec, loc, lock, tar, ini, fee); //need the lock
            participants[i].lastSentTransfer.sender = ecrecovery(h, sig);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            var(non, exp, ass, rec) = decodeCancelTransfer1(message);
            var(loc, bal, amo, has, sig) = decodeCancelTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfer.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfer.asset = ass;
            participants[i].lastSentTransfer.recipient = rec;
            participants[i].lastSentTransfer.locksroot = loc;
            participants[i].lastSentTransfer.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            bytes32 h = sha3(non, add, bal, rec, loc, lock); //need the lock
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

    // empty function to handle wrong calls
    function () { throw; }
}
