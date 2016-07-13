import "StandardToken.sol";
import "Dcdr.sol";

contract NettingChannelContract {
    uint public settleTimeout;
    address public assetAddress;
    uint public opened;
    uint public closed;
    uint public settled;
    address public closingAddress;
    StandardToken public assetToken;

    struct Lock
    {
        uint8 expiration;
        uint amount;
        bytes32 hashlock;
    }
    struct Participant
    {
        address addr; // 0
        uint deposit; // 1
        uint netted; // 2
        uint transferedAmount; // 3
        uint amount; // 4
        bytes merkleProof; // 5
        bytes32 hashlock; // 6
        bytes32 secret; // 7
        uint expiration; // 8
        address sender; // 9
        uint nonce; // 10
        address asset; // 11
        address recipient; // 12
        bytes32 locksroot; // 13
        Lock[] unlocked; //14
    }
    Participant[2] public participants; // We only have two participants at all times

    event ChannelNewBalance(address assetAddress, address participant, uint balance);
    event ChannelClosed(address closingAddress, uint blockNumber);
    event ChannelSettled(uint blockNumber);
    event ChannelSecretRevealed(bytes32 secret); //TODO

    /// @dev modifier ensuring that only a participant of the channel can call a function
    modifier inParticipants {
        if (msg.sender != participants[0].addr &&
            msg.sender != participants[1].addr) throw;
        _
    }

    /// @dev modifier ensuring that function can only be called if a channel
    /// is closed, but not yet settled.
    modifier notSettledOrClosed {
        // if channel is already settled or hasn't been closed yet
        if (settled > 0 || closed == 0) throw;
        _
    }

    function NettingChannelContract(address assetAdr, address participant1, address participant2, uint timeout) {
        assetToken = StandardToken(assetAdr);
        assetAddress = assetAdr;
        participants[0].addr = participant1;
        participants[1].addr = participant2;

        if (timeout < 30) {
            settleTimeout = 30;
        } else {
            settleTimeout = timeout;
        }
    }

    /// @notice atIndex(address) to get the index of an address (0 or 1)
    /// @dev get the index of an address
    /// @param addr (address) the address you want the index of
    function atIndex(address addr) private returns (uint index) {
        if (addr == participants[0].addr) return 0;
        if (addr == participants[1].addr) return 1;
        else throw;
    }

    /// @notice deposit(uint) to deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants
    /// must deposit before the channel is opened.
    /// @param amount (uint) the amount to be deposited to the address
    function deposit(uint256 amount) inParticipants {
        if (closed != 0) {
            throw;
        }

        if (assetToken.balanceOf(msg.sender) < amount) {
            throw;
        }

        bool success = assetToken.transferFrom(
            msg.sender,
            address(this),
            amount
        );

        if (success == true) {
            uint index = atIndex(msg.sender);
            Participant participant = participants[index];
            uint deposit = participant.deposit;

            deposit += amount;
            participant.deposit = deposit;

            if (opened == 0) {
                opened = block.number;
            }

            ChannelNewBalance(assetAddress, msg.sender, deposit);
        }
    }

    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() private constant returns (bool) {
        if (closed > 0) throw;
        if (participants[0].deposit > 0 || participants[1].deposit > 0) return true;
        else return false;
    }

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @param ownAddress (address) address of the calling party
    /// @return partnerAddress (address) the partner of the calling party
    function partner(address ownAddress) private returns (address partnerAddress) {
        if (ownAddress == participants[0].addr) return participants[1].addr;
        else return participants[0].addr;
    }

    /// @notice addressAndBalance() to get the addresses and deposits of the participants
    /// @dev get the addresses and deposits of the participants
    /// @return par1 (address) address of one of the participants
    /// @return par2 (address) address of the the other participant
    /// @return dep1 (uint) the deposit of the first participant
    /// @return dep2 (uint) the deposit of the second participant
    function addressAndBalance() constant returns (address par1, uint dep1, address par2, uint dep2) {
        par1 = participants[0].addr;
        dep1 = participants[0].deposit;
        par2 = participants[1].addr;
        dep2 = participants[1].deposit;
    }

    /// @notice close(bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    function closeSingleFunded(bytes firstEncoded) inParticipants { 
        // TODO modifier
        if (settled > 0) throw; // channel already settled
        if (closed > 0) throw; // close has already been called

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
        ChannelClosed(closingAddress, closed);
    }

    /// @notice close(bytes, bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    /// @param secondEncoded (bytes) the last sent transfer of the msg.sender
    function closeBiFunded(bytes firstEncoded, bytes secondEncoded) inParticipants { 
        if (settled > 0) throw; // channel already settled
        if (closed > 0) throw; // close has already been called
        address firstSender = getSender(firstEncoded);
        address secondSender = getSender(secondEncoded);

        // Don't allow both transfers to be from the same sender
        if (firstSender == secondSender) throw;

        // check if the sender of either of the messages is a participant
        if (firstSender != participants[0].addr &&
            firstSender != participants[1].addr) throw;
        if (secondSender != participants[0].addr &&
            secondSender!= participants[1].addr) throw;

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
        ChannelClosed(closingAddress, closed);
    }

    /// @notice updateTransfer(bytes) to update last known transfer
    /// @dev Allow the partner to update the last known transfer
    /// @param message (bytes) the encoded transfer message
    function updateTransfer(bytes message) inParticipants notSettledOrClosed {
        if (closed + settleTimeout < block.number) throw; //if locked time has expired throw
        if (msg.sender == closingAddress) throw; // don't allow closer to update
        if (closingAddress == getSender(message)) throw;

        uint8 nonce = bytesToIntEight(slice(message, 4, 12), nonce);
        uint sender = atIndex(msg.sender);
        if (nonce < participants[sender].nonce) throw;
        decode(message);

        // TODO check if tampered and penalize
        // TODO check if outdated and penalize
    }

    /// @notice unlock(bytes, bytes, bytes32) to unlock a locked transfer
    /// @dev Unlock a locked transfer
    /// @param lockedEncoded (bytes) the lock
    /// @param merkleProof (bytes) the merkle proof
    /// @param secret (bytes32) the secret
    /*
    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) inParticipants notSettledOrClosed {
        var(expiration, amount, hashlock) = decodeLock(lockedEncoded);
        if (expiration > closed) throw;
        if (hashlock != sha3(secret)) throw;

        uint partnerId = atIndex(partner(msg.sender));

        if (participants[partnerId].nonce == 0) throw;

        // merkle proof
        bytes32 h = sha3(lockedEncoded);
        bytes32 single;
        single = bytesToBytes32(merkleProof, single);
        if (merkleProof.length == 32 && h != single) throw; 
        for (uint i = 0; i < merkleProof.length; i += 64) {
            bytes32 left;
            left = bytesToBytes32(slice(merkleProof, i, i + 32), left);
            bytes32 right;
            right = bytesToBytes32(slice(merkleProof, i + 32, i + 64), right);
            if (h != left && h != right) throw;
            h = sha3(left, right);
        }

        if (participants[partnerId].locksroot != h) throw;

        ChannelSecretRevealed(secret);
        participants[partnerId].unlocked.push(Lock(expiration, amount, hashlock));
    }
    */
    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) inParticipants notSettledOrClosed {
        uint partnerId;
        bytes32 h;
        bytes32 el;

        var (expiration, amount, hashlock) = Dcdr.decodeLock(lockedEncoded);

        if (expiration > closed) {
            throw;
        }

        if (hashlock != sha3(secret)) {
            throw;
        }

        partnerId = atIndex(partner(msg.sender));

        if (participants[partnerId].nonce == 0) {
            throw;
        }

        h = sha3(lockedEncoded);
        for (uint i = 0; i < merkleProof.length; i += 32) {
            el = bytesToBytes32(slice(merkleProof, i, i + 32), el);

            if (h < el) {
                h = sha3(h, el);
            } else {
                h = sha3(el, h);
            }
        }

        // TODO 
        /*if (participants[partnerId].locksroot != h) {*/
            /*throw;*/
        /*}*/

        ChannelSecretRevealed(secret);
        participants[partnerId].unlocked.push(Lock(expiration, amount, hashlock));
    }
    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[]) the participants with netted balances
    function settle() inParticipants notSettledOrClosed {
        if (closed + settleTimeout < block.number) throw; //timeout is not yet over

        // update the netted balance of both participants
        for (uint i = 0; i < 2; i++) { // Always exactly two participants
            participants[i].netted = getNetted(i);
        }

        // Update the netted balance from the locks
        for (uint j = 0; j < 2; j++) { // Always exactly two participants
            uint otherIdx;
            if (j == 0) otherIdx = 1; else otherIdx = 0;
            for (uint k = 0; k < participants[j].unlocked.length; k++) {
                participants[j].netted += participants[j].unlocked[k].amount;
                participants[otherIdx].netted -= participants[j].unlocked[k].amount;
            }
        }
        settled = block.number;
        payOut();
        // trigger event
        ChannelSettled(settled);
    }

    function payOut() private {
        uint totalNetted = participants[0].netted + participants[1].netted;
        uint totalDeposit = participants[0].deposit + participants[1].deposit;
        if (totalNetted > totalDeposit) throw;
        assetToken.transfer(participants[0].addr, participants[0].netted);
        assetToken.transfer(participants[1].addr, participants[1].netted);
    }

    function getNetted(uint i) private returns (uint netted) {
        uint other;
        if (i == 0) other = 1; else other = 0;
        uint ownDeposit = participants[i].deposit;
        uint otherTransferedAmount = participants[other].transferedAmount;
        uint ownTransferedAmount = participants[i].transferedAmount;
        netted = ownDeposit + otherTransferedAmount - ownTransferedAmount;
    }

    function decode(bytes message) private {
        address sender;
        // Secret
        if (decideCMD(message) == 4) {
            assignSecret(message);
        }
        // Direct Transfer
        if (decideCMD(message) == 5) {
            assignDirect(message);
        }
        // Locked Transfer
        if (decideCMD(message) == 6) {
            assignLocked(message);
        }
        // Mediated Transfer
        if (decideCMD(message) == 7) {
            sender = assignMediated1(message);
            assignMediated2(message, sender);
        }
        // Cancel Transfer
        if (decideCMD(message) == 8) {
            assignCancel(message);
        }
        /*else throw;*/
    }

    function decideCMD(bytes message) private returns (uint number) {
        number = uint(message[0]);
    }

    function assignSecret(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(sec) = Dcdr.decodeSecret(message);
        participants[atIndex(msg.sender)].secret = sec;
        participants[i].sender = sender;
    }
    function assignDirect(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(cmd, non, ass, rec, trn, loc, sec) = Dcdr.decodeTransfer(message);
        participants[i].nonce = non;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].transferedAmount = trn;
        participants[i].locksroot = loc;
        participants[i].secret = sec;
        participants[i].sender = sender;
    }
    function assignLocked(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(non, exp, ass, rec, loc, trn, amo, has) = Dcdr.decodeLockedTransfer(message);
        participants[i].nonce = non;
        participants[i].expiration = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].locksroot = loc;
        participants[i].transferedAmount = trn;
        participants[i].amount = amo;
        participants[i].hashlock = has;
        participants[i].sender = sender;
    }
    function assignMediated1(bytes message) private returns (address sender) {
        sender = getSender(message);
        uint i = atIndex(sender);
        var(non, exp, ass, rec, tar, ini, loc) = Dcdr.decodeMediatedTransfer1(message); 
        participants[i].nonce = non;
        participants[i].expiration = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].locksroot = loc;
    }
    function assignMediated2(bytes message, address sender) private {
        bytes32 lock;
        uint i = atIndex(sender);
        var(has, trn, amo, fee) = Dcdr.decodeMediatedTransfer2(message);
        participants[i].hashlock = has;
        participants[i].transferedAmount = trn;
        participants[i].amount = amo;
        participants[i].sender = sender;
    }
    function assignCancel(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(non, exp, ass, rec, loc, trn, amo, has) = Dcdr.decodeCancelTransfer(message);
        participants[i].nonce = non;
        participants[i].expiration = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].locksroot = loc;
        participants[i].transferedAmount = trn;
        participants[i].amount = amo;
        participants[i].hashlock = has;
        participants[i].sender = sender;
    }

    // Gets the sender of a last sent transfer
    function getSender(bytes message) returns (address sndr) {
        bytes memory mes;
        bytes memory sig;
        // Secret
        if (decideCMD(message) == 4) {
            mes = slice(message, 0, 36);
            sig = slice(message, 36, 101);
            sndr = ecRec(mes, sig);
        }
        // Direct Transfer
        if (decideCMD(message) == 5) {
            mes = slice(message, 0, 148);
            sig = slice(message, 148, 213);
            sndr = ecRec(mes, sig);
        }
        // Locked Transfer
        if (decideCMD(message) == 6) {
            mes = slice(message, 0, 188);
            sig = slice(message, 188, 253);
            sndr = ecRec(mes, sig);
        }
        // Mediated Transfer
        if (decideCMD(message) == 7) {
            mes = slice(message, 0, 260);
            sig = slice(message, 260, 325);
            sndr = ecRec(mes, sig);
        }
        // Cancel Transfer
        if (decideCMD(message) == 8) {
            mes = slice(message, 0, 188);
            sig = slice(message, 188, 253);
            sndr = ecRec(mes, sig);
        }
        /*else throw;*/
    }

    // Function for ECRecovery
    function ecRec(bytes message, bytes sig) private returns (address sndr) {
        bytes32 hash = sha3(message);
        var(r, s, v) = sigSplit(sig);
        sndr = ecrecover(hash, v, r, s);
    }

    /* HELPER FUNCTIONS */
    function sigSplit(bytes message) private returns (bytes32 r, bytes32 s, uint8 v) {
        if (message.length != 65) throw;

        // The signature format is a compact form of:
        //   {bytes32 r}{bytes32 s}{uint8 v}
        // Compact means, uint8 is not padded to 32 bytes.
        assembly {
            r := mload(add(message, 32))
            s := mload(add(message, 64))
            // Here we are loading the last 32 bytes, including 31 bytes
            // of 's'. There is no 'mload8' to do this.
            //
            // 'byte' is not working due to the Solidity parser, so lets
            // use the second best option, 'and'
            v := and(mload(add(message, 65)), 1)

        }
        // old geth sends a `v` value of [0,1], while the new, in line with the YP sends [27,28]
        if(v < 27) v += 27;
    }

    function slice(bytes a, uint start, uint end) private returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    function bytesToIntEight(bytes b, uint8 i) private returns (uint8 res) {
        assembly { i := mload(add(b, 0x8)) }
        res = i;
    }

    function bytesToBytes32(bytes b, bytes32 i) private returns (bytes32 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }

    // empty function to handle wrong calls
    function () { throw; }
}
