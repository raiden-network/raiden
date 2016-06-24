import "StandardToken.sol";

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

    event ChannelOpened(address assetAdr, address participant1,
                        address participant2, uint deposit1, uint deposit2);
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
    modifier notSettled {
        // if channel is already settled or hasn't been closed yet
        if (settled > 0 || closed == 0) throw;
        _
    }

    function NettingChannelContract(address assetAdr, address participant1, address participant2, uint timeout) {
        assetToken = StandardToken(assetAdr);
        assetAddress = assetAdr;
        participants[0].addr = participant1;
        participants[1].addr = participant2;
        if (settleTimeout < 30) settleTimeout = 30; else settleTimeout = timeout;
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
        if (assetToken.balanceOf(msg.sender) <= amount) throw;
        bool s = assetToken.transferFrom(msg.sender, address(this), amount);
        if (s == true) participants[atIndex(msg.sender)].deposit += amount;
        if(isOpen() && opened == 0) open();
    }

    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() private returns (bool) {
        if (closed > 0) throw;
        if (participants[0].deposit > 0 || participants[1].deposit > 0) return true;
        else return false;
    }

    /// @notice open() to set the opened to be the current block and triggers 
    /// the event ChannelOpened()
    /// @dev Sets the value of `opened` to be the value of the current block.
    /// param none
    /// returns none, but changes the value of `opened` and triggers the event ChannelOpened.
    function open() private {
        opened = block.number;
        // trigger event
        ChannelOpened(assetAddress, participants[0].addr, 
                      participants[1].addr, participants[0].deposit, participants[1].deposit);
    }

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return p (address) the partner of the calling party
    function partner(address a) private returns (address p) {
        if (a == participants[0].addr) return participants[1].addr;
        else return participants[0].addr;
    }

    /// @notice addrAndDep() to get the addresses and deposits of the participants
    /// @dev get the addresses and deposits of the participants
    /// @return par1 (address) address of one of the participants
    /// @return par2 (address) address of the the other participant
    /// @return dep1 (uint) the deposit of the first participant
    /// @return dep2 (uint) the deposit of the second participant
    function addrAndDep() returns (address par1, uint dep1, address par2, uint dep2) {
        par1 = participants[0].addr;
        dep1 = participants[0].deposit;
        par2 = participants[1].addr;
        dep2 = participants[1].deposit;
    }

    /// @notice close(bytes) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param firstEncoded (bytes) the last sent transfer of the msg.sender
    function closeSingleFunded(bytes firstEncoded) inParticipants { 
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
    function updateTransfer(bytes message) inParticipants notSettled {
        if (closed + settleTimeout > block.number) throw; //if locked time has expired throw
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
    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) inParticipants notSettled{
        var(expiration, amount, hashlock) = decodeLock(lockedEncoded);
        if (expiration > closed) throw;
        if (hashlock != sha3(secret)) throw;

        uint partnerId = atIndex(partner(msg.sender));
        uint senderId = atIndex(msg.sender);

        if (participants[partnerId].nonce == 0) throw;

        // merkle proof
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

        ChannelSecretRevealed(secret);
        participants[partnerId].unlocked.push(Lock(expiration, amount, hashlock));
    }

    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[]) the participants with netted balances
    function settle() inParticipants notSettled {
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
        var(sec) = decodeSecret(message);
        participants[atIndex(msg.sender)].secret = sec;
        participants[i].sender = sender;
    }
    function assignDirect(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(cmd, non, ass, rec, trn, loc, sec) = decodeTransfer(message);
        participants[i].nonce = non;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].transferedAmount = trn;
        participants[i].hashlock = loc;
        participants[i].secret = sec;
        participants[i].sender = sender;
    }
    function assignLocked(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(non, exp, ass, rec, loc, trn, amo, has) = decodeLockedTransfer(message);
        participants[i].nonce = non;
        settleTimeout = exp;
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
        var(non, exp, ass, rec, tar, ini, loc) = decodeMediatedTransfer1(message); 
        participants[i].nonce = non;
        settleTimeout = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].locksroot = loc;
    }
    function assignMediated2(bytes message, address sender) private {
        bytes32 lock;
        uint i = atIndex(sender);
        var(has, trn, amo, fee) = decodeMediatedTransfer2(message);
        participants[i].hashlock = has;
        participants[i].transferedAmount = trn;
        participants[i].amount = amo;
        participants[i].sender = sender;
    }
    function assignCancel(bytes message) private {
        address sender = getSender(message);
        uint i = atIndex(sender);
        var(non, exp, ass, rec, loc, trn, amo, has) = decodeCancelTransfer(message);
        participants[i].nonce = non;
        settleTimeout = exp;
        participants[i].asset = ass;
        participants[i].recipient = rec;
        participants[i].locksroot = loc;
        participants[i].transferedAmount = trn;
        participants[i].transferedAmount = amo;
        participants[i].hashlock = has;
        participants[i].sender = sender;
    }

    /* DECODERS */

    function decodeSecret(bytes m) returns (bytes32 secret) {
        if (m.length != 101) throw;
        secret = bytesToBytes32(slice(m, 4, 36), secret);
    }

    function decodeTransfer(bytes m)
        returns
        (bytes4 cmdIdPad,
        uint8 nonce,
        address asset,
        address recipient,
        uint transferedAmount,
        bytes32 optionalLocksroot,
        bytes32 optionalSecret)
    {
        if (m.length != 213) throw;
        cmdIdPad = bytesToBytes4(slice(m, 0, 4), cmdIdPad);
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        uint160 ia;
        asset = bytesToAddress(slice(m, 12, 32), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 32, 52), ir);
        transferedAmount = bytesToInt(slice(m, 52, 84), transferedAmount);
        optionalLocksroot = bytesToBytes32(slice(m, 84, 116), optionalLocksroot);
        optionalSecret = bytesToBytes32(slice(m, 116, 148), optionalSecret);
    }

    function decodeLockedTransfer(bytes m)
        returns
        (uint8 nonce,
        uint8 expiration,
        address asset,
        address recipient,
        bytes32 locksroot,
        uint transferedAmount,
        uint amount,
        bytes32 hashlock)
    {
        if (m.length != 253) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
        locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
        transferedAmount = bytesToInt(slice(m, 92, 124), transferedAmount);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
    }

    function decodeMediatedTransfer1(bytes m) 
        returns
        (uint8 nonce,
        uint8 expiration,
        address asset,
        address recipient,
        address target,
        address initiator,
        bytes32 locksroot)
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
        uint160 ii;
        initiator = bytesToAddress(slice(m, 80, 100), ii);
        locksroot = bytesToBytes32(slice(m, 100, 132), locksroot);
    }

    function decodeMediatedTransfer2(bytes m) 
        returns
        (bytes32 hashlock,
        uint transferedAmount,
        uint amount,
        uint fee)
    {
        if (m.length != 325) throw;
        hashlock = bytesToBytes32(slice(m, 132, 164), hashlock);
        transferedAmount = bytesToInt(slice(m, 164, 196), transferedAmount);
        amount = bytesToInt(slice(m, 196, 228), amount);
        fee = bytesToInt(slice(m, 228, 260), fee);
    }

    function decodeCancelTransfer(bytes m) 
        returns
        (uint8 nonce,
        uint8 expiration,
        address asset,
        address recipient,
        bytes32 locksroot,
        uint transferedAmount,
        uint amount,
        bytes32 hashlock)
    {
        if (m.length != 253) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
        locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
        transferedAmount = bytesToInt(slice(m, 92, 124), transferedAmount);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
    }

    function decodeLock(bytes m)
        returns
        (uint8 expiration,
        uint amount,
        bytes32 hashlock)
    {
        if (m.length != 62) throw;
        expiration = bytesToIntEight(slice(m, 0, 8), expiration);
        amount = bytesToInt(slice(m, 8, 40), amount);
        hashlock = bytesToBytes32(slice(m, 40, 62), hashlock);
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

    function bytesToInt(bytes b, uint i) private returns (uint res) {
        assembly { i := mload(add(b, 0x20)) }
        res = i;
    }

    function bytesToAddress(bytes b, uint160 i) private returns (address add) {
        assembly { i := mload(add(b, 0x14)) }
        uint160 a = uint160(i);
        add = address(i);
    }

    function bytesToBytes4(bytes b, bytes4 i) private returns (bytes4 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }

    function bytesToBytes32(bytes b, bytes32 i) private returns (bytes32 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }

    // empty function to handle wrong calls
    function () { throw; }
}
