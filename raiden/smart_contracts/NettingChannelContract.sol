contract NettingChannelContract {
    uint public lockedTime;
    address public assetAddress;
    uint public opened;
    uint public closed;
    uint public settled;
    address public closingAddress;


    struct Participant
    {
        address addr;
        uint deposit;
        uint netted;
        uint transferedAmount;
        bytes merkleProof;
        bytes32 hashlock;
        bytes32 secret;
        uint expiration;
        address sender;
        uint nonce;
        address asset;
        uint balance;
        address recipient;
        bytes32 locksroot;
    }
    Participant[2] public participants; // We only have two participants at all times

    event ChannelOpened(address assetAdr); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO
    event ChannelSecretRevealed(); //TODO
    
    modifier inParticipants {
        if (msg.sender != participants[0].addr &&
            msg.sender != participants[1].addr) throw;
        _
    }

    function NettingChannelContract(address assetAdr, address participant1, address participant2) {
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

        if (participants[partnerId].nonce == 0) throw;

        bytes32 h = sha3(lockedEncoded);

        for (uint i = 0; i < merkleProof.length; i += 64) {
            bytes32 left;
            left = bytesToBytes32(slice(merkleProof, i, i + 32), left);
            bytes32 right;
            right = bytesToBytes32(slice(merkleProof, i + 32, i + 64), right);
            if (h != left && h != right) throw;
            h = sha3(left, right);
        }

        if (participants[partnerId].locksroot != h) throw;

        // TODO decode lockedEncoded into a Unlocked struct and append
        
        //participants[partnerId].unlocked.push(lock);
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
            sndr = dsec(message);
        }
        // Direct Transfer
        if (message[0] == 5) {
            sndr = ddtran(message);
        }
        // Locked Transfer
        if (message[0] == 6) {
            sndr = dltran(message);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            sndr = dmtran(message);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            sndr = dctran(message);
        }
        else throw;
    }

    function dsec(bytes message) returns (address sndr) {
        var(sec, sig) = decodeSecret(message);
        bytes32 h = sha3(sec);
        sndr = ecrecovery(h, sig);
    }
    function ddtran(bytes message) returns (address sndr) {
        var(non, ass, rec, bal, olo, , sig) = decodeTransfer(message);
        bytes32 h = sha3(non, ass, bal, rec, olo); //need the optionalLocksroot
        sndr = ecrecovery(h, sig);
    }
    function dltran(bytes message) returns (address sndr) {
        bytes32 lock;
        var(non, , ass, rec) = decodeLockedTransfer1(message);
        var(loc, bal, , has, sig) = decodeLockedTransfer2(message);
        bytes32 h = sha3(non, ass, bal, rec, loc, lock ); //need the lock
        sndr = ecrecovery(h, sig);
    }
    function dmtran(bytes message) returns (address sndr) {
        bytes32 lock;
        var(non, , ass, rec, tar) = decodeMediatedTransfer1(message); 
        var(ini, loc, bal, , , fee, sig) = decodeMediatedTransfer2(message);
        bytes32 h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
        sndr = ecrecovery(h, sig);
    }
    function dctran(bytes message) returns (address sndr) {
        bytes32 lock;
        var(non, , ass, rec) = decodeCancelTransfer1(message);
        var(loc, bal, , , sig) = decodeCancelTransfer2(message);
        bytes32 h = sha3(non, ass, bal, rec, loc, lock); //need the lock
        sndr = ecrecovery(h, sig);
    }


    function decode(bytes message) {
        bytes32 hash;
        // Secret
        uint i;
        if (message[0] == 4) {
            decsec(message);
        }
        // Direct Transfer
        if (message[0] == 5) {
            decdir(message);
        }
        // Locked Transfer
        if (message[0] == 6) {
            hash = decloc1(message);
            decloc2(message, hash);
        }
        // Mediated Transfer
        if (message[0] == 7) {
            hash = decmed1(message);
            decmed2(message, hash);
        }
        // Cancel Transfer
        if (message[0] == 8) {
            hash = deccan1(message);
            deccan2(message, hash);
        }
        else throw;
    }

    function decsec(bytes message) {
        uint i = atIndex(getSender(message));
        var(sec, sig) = decodeSecret(message);
        participants[atIndex(msg.sender)].secret = sec;
        bytes32 h = sha3(sec);
        participants[i].sender = ecrecovery(h, sig);
    }
    function decdir(bytes message) {
        bytes32 lock;
        uint i = atIndex(getSender(message));
        var(non, ass, rec, bal, loc, sec, sig) = decodeTransfer(message);
        participants[i].nonce = non;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].balance = bal;
        bytes32 h = sha3(non, ass, bal, rec, loc);
        participants[i].sender = ecrecovery(h, sig);
    }
    function decloc1(bytes message) returns (bytes32 hh) {
        uint i = atIndex(getSender(message));
        var(non, exp, ass, rec) = decodeLockedTransfer1(message);
        participants[i].nonce = non;
        lockedTime = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        hh = sha3(non, ass, rec);
    }
    function decloc2(bytes message, bytes32 hh) {
        bytes32 lock;
        uint i = atIndex(getSender(message));
        var(loc, bal, amo, has, sig) = decodeLockedTransfer2(message);
        participants[i].locksroot = loc;
        participants[i].balance = bal;
        participants[i].transferedAmount = amo;
        participants[i].hashlock = has;
        bytes32 h = sha3(hh, bal, loc, lock ); //need the lock
        participants[i].sender = ecrecovery(h, sig);
    }
    function decmed1(bytes message) returns (bytes32 hh) {
        uint i = atIndex(getSender(message));
        var(non, exp, ass, rec, tar) = decodeMediatedTransfer1(message); 
        participants[i].nonce = non;
        lockedTime = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        hh = sha3(non, ass, rec, tar);
    }
    function decmed2(bytes message, bytes32 hh) {
        bytes32 lock;
        uint i = atIndex(getSender(message));
        var(ini, loc, has, bal, amo, fee, sig) = decodeMediatedTransfer2(message);
        participants[i].locksroot = loc;
        participants[i].hashlock = has;
        participants[i].balance = bal;
        participants[i].transferedAmount = amo;
        bytes32 h = sha3(hh, bal, loc, lock, ini, fee); //need the lock
        participants[i].sender = ecrecovery(h, sig);
    }
    function deccan1(bytes message) returns (bytes32 hh) {
        uint i = atIndex(getSender(message));
        var(non, exp, ass, rec) = decodeCancelTransfer1(message);
        participants[i].nonce = non;
        lockedTime = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        hh = sha3(non, ass, rec);
    }
    function deccan2(bytes message, bytes32 hh) {
        bytes32 lock;
        uint i = atIndex(getSender(message));
        var(loc, bal, amo, has, sig) = decodeCancelTransfer2(message);
        participants[i].locksroot = loc;
        participants[i].balance = bal;
        participants[i].transferedAmount = amo;
        participants[i].hashlock = has;
        bytes32 h = sha3(hh, bal, loc, lock); //need the lock
        participants[i].sender = ecrecovery(h, sig);
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
    
    function decodeSecret(bytes m) returns (bytes32 secret, bytes signature) {
        if (m.length != 101) throw;
        secret = bytesToBytes32(slice(m, 4, 36), secret);
        signature = slice(m, 36, 101);
    }
    
    function decodeTransfer(bytes m) returns (uint8 nonce, address asset, address recipient,
                                                uint balance, bytes32 optionalLocksroot,
                                                bytes32 optionalSecret, bytes signature) 
    {
        if (m.length != 213) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        uint160 ia;
        asset = bytesToAddress(slice(m, 12, 32), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 32, 52), ir);
        balance = bytesToInt(slice(m, 52, 84), balance);
        optionalLocksroot = bytesToBytes32(slice(m, 84, 116), optionalLocksroot);
        optionalSecret = bytesToBytes32(slice(m, 116, 148), optionalSecret);
        signature = slice(m, 148, 213);

    }
    
    function decodeLockedTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                        address asset, address recipient) 
    {
        if (m.length != 253) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
        
    }
    
    function decodeLockedTransfer2(bytes m) returns 
                                    (bytes32 locksroot, uint balance, uint amount,
                                        bytes32 hashlock, bytes signature) 
    {

        locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
        balance = bytesToInt(slice(m, 92, 124), balance);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
        signature = slice(m, 188, 253);
    }
    
    function decodeMediatedTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                        address asset, address recipient,
                                                        address target) 
    {
        if (m.length != 325) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
        uint160 it;
        target = bytesToAddress(slice(m, 60, 80), it);
        
    }
    
    function decodeMediatedTransfer2(bytes m) returns 
                                    (address initiator, bytes32 locksroot, bytes32 hashlock, 
                                        uint balance, uint amount, uint fee, bytes signature) 
    {
        uint160 ii;
        initiator = bytesToAddress(slice(m, 80, 100), ii);
        locksroot = bytesToBytes32(slice(m, 100, 132), locksroot);
        hashlock = bytesToBytes32(slice(m, 132, 164), hashlock);
        balance = bytesToInt(slice(m, 164, 196), balance);
        amount = bytesToInt(slice(m, 196, 228), amount);
        fee = bytesToInt(slice(m, 228, 260), fee);
        signature = slice(m, 260, 325);
    }
    
    function decodeCancelTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                                address asset, address recipient) 
    {
        if (m.length != 253) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
    }
    
    function decodeCancelTransfer2(bytes m) returns (bytes32 locksroot, uint balance, 
                                                        uint amount, bytes32 hashlock, bytes signature) 
    {
        locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
        balance = bytesToInt(slice(m, 92, 124), balance);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
        signature = slice(m, 188, 253); 
    }
    
    /* HELPER FUNCTIONS */
    
    function bytesToIntEight(bytes b, uint8 i) returns (uint8 res) {
        assembly { i := mload(add(b, 0x8)) }
        res = i;
    }
    
    // helper function
    function bytesToInt(bytes b, uint i) returns (uint res) {
        assembly { i := mload(add(b, 0x20)) }
        res = i;
    }
    
    // helper function
    function bytesToAddress(bytes b, uint160 i) returns (address add) {
        assembly { i := mload(add(b, 0x14)) }
        uint160 a = uint160(i);
        add = address(i);
    }
    
    function bytesToBytes32(bytes b, bytes32 i) returns (bytes32 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }

    // empty function to handle wrong calls
    function () { throw; }
}
