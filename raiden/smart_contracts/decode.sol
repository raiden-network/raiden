library Decoder {
    
    function slice(bytes a, uint start, uint end) returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        if (start > end) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    // Should be called directly from nettingChannelContract.sol
    function decode(bytes message) {
        // Secret
        if (message[0] == 4) {
            var(sec, sig) = decodeSecret(message);
            participants[atIndex(msg.sender)].lastSentTransfers.secret = sec;
            // what to do with signature?
        }
        // Transfer
        if (message[0] == 5) decodeTransfer(message);
        // Locked Transfer
        if (message[0] == 6) {
            var(non, exp, ass, rec) = decodeLockedTransfer1(message);
            var(loc, bal, amo, has, sig) = decodeLockedTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfers.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfers.asset = ass;
            participants[i].lastSentTransfers.recipient = rec;
            participants[i].lastSentTransfers.locksroot = loc;
            participants[i].lastSentTransfers.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            // What to do with sig?
        }
        // Mediated Transfer
        if (message[0] == 7) {
            var(non, exp, ass, rec, tar) = decodeMediatedTransfer1(message); 
            var(ini, loc, has, bal, amo, fee, sig) = decodeMediatedTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfers.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfers.asset = ass;
            participants[i].lastSentTransfers.recipient = rec;
            // target not needed?
            // initiator not needed?
            participants[i].lastSentTransfers.locksroot = loc;
            participants[i].unlocked.hashlock = has;
            participants[i].lastSentTransfers.balance = bal;
            // amount not needed?
            // fee not needed?
            // What to do with sig?
        }
        // Cancel Transfer
        if (message[0] == 8) {
            var(non, exp, ass, rec) = decodeCancelTransfer1(message);
            var(loc, bal, amo, has, sig) = decodeCancelTransfer2(message);
            uint i = atIndex(msg.sender);
            participants[i].lastSentTransfers.nonce = non;
            lockedTime = exp;
            participants[i].lastSentTransfers.asset = ass;
            participants[i].lastSentTransfers.recipient = rec;
            participants[i].lastSentTransfers.locksroot = loc;
            participants[i].lastSentTransfers.balance = bal;
            /*participants[i].unlocked.amount = amo; // not sure we need this*/
            participants[i].unlocked.hashlock = has;
            // What to do with sig?
        }
        else throw;
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
        if (m.length != 315) throw;
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
        signature = slice(m, 260, 315);
    }
    
    function decodeCancelTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                               address asset, address recipient) 
    {
        //if (m.length != 253) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
    }
    
    function decodeCancelTransfer2(bytes m) returns (bytes32 locksroot, uint balance, 
                                                     uint amount, bytes32 hashlock) 
    {
        locksroot = bytesToBytes32(slice(m, 60, 92), locksroot);
        balance = bytesToInt(slice(m, 92, 124), balance);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = bytesToBytes32(slice(m, 156, 188), hashlock);
        //signature = slice(m, 188, 253); //not working for tests right now, since 
                                          // bytes encoding is buggy
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
    
    /* TESTS */
    
    bytes secret = "\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00secret\xd3{G\xb4k\xea\x90'\xa9*n\x1c7DP\t \x16\xb9\x93\\\x0f\x1es\x8a\x95\x16i?p\x8f[5\x93{\xb4\xe0\xa7\xde\x93\xbe1X^j\xa0I\x84\x86\x94w\xceR\x83A]NsnS~Y\xd45\x01";
    bytes cancelTrans = "\x08\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x1f\x0b\xd4\x06\x06\x88\xa1\x80\n\xe9\x86\xe4\x84\n\xeb\xc9$\xbb@\xb5\xbf8\x93&;\xf8\xb2\xd07:4\xb8\xd3Y\xc5\xed\xd8#\x11\x07G`\xd0\x9bF\x87\xc1b\x15K)\x0e\xe5\xfc\xbd|b\x85Y\ti\xb3\xc8s\xe9Ki\x0e\xe9\xc4\xf5\xdfQ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x1dV\x01\xc4G_/j\xa7=jp\xa5o\x9cuo$\xd2\x11\xa9\x14\xccz\xff?\xb8\r-\x87A\xc8h\xf4\x96o\xe9;F}(\xf1[\xef\xd48\xb7\xaa\x0e{\x8f\xbf_\x00\xce\x1a\xbe\x0c\xc4\xa0\xdd\xf9\xbc\xc7\xc4\x01";

    function testDecide() returns (bool yay, bool isCancel, string secr) {
        yay = secret[0] == 4;
        isCancel = cancelTrans[0] == 8;
        bytes memory b = slice(secret, 30, 36);
        string memory s = string(b);
        secr = s;
    }
    
    // TODO
    // FAILING TESTS
    function testDecodeSecret() returns (bytes32 secr, bytes sig, bool isSig, bool isSec, bytes sigb) {
        (secr, sig) = decodeSecret(secret);
        sigb = "d37b47b46bea9027a92a6e1c374450092016b9935c0f1e738a9516693f708f5b35937bb4e0a7de93be31585e6aa04984869477ce5283415d4e736e537e59d43501";
    }
    
    function testAsset() returns (bool isAsset, address addr) {
        (, , addr, ) = decodeCancelTransfer1(cancelTrans);
        isAsset = addr == 0x0bd4060688a1800ae986e4840aebc924bb40b5bf;
    } 
    
    function testNonce() returns (bool isInteger, uint nonce) {
        (nonce, , , ) = decodeCancelTransfer1(cancelTrans);
        isInteger = nonce == 1;
    }
    
    function testExpiration() returns (bool isInteger, uint expiration) {
        (, expiration, ,) = decodeCancelTransfer1(cancelTrans);
        isInteger = expiration == 31;
    }
        
    function testRecipient() returns (bool isRecipient, address recipient) {
        (, , , recipient) = decodeCancelTransfer1(cancelTrans);
        isRecipient = recipient == 0x3893263bf8b2d0373a34b8d359c5edd823110747;
    } 
    
    // not passing. Need to find proper way to caompare bytes and bytes from sample input
    function testLocksroot() returns (bytes32 locksroot, bool isLocksroot, bytes lcrt) {
        (locksroot, , , ) = decodeCancelTransfer2(cancelTrans);
        lcrt = "60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51";
        //isLocksroot = compareBytes(locksroot, lcrt) == 0;
    } 
}
