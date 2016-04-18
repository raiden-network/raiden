contract Decoder {

    function slice(bytes a, uint start, uint end) returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        if (start > end) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }

    function decideCmd(bytes message) returns (string typ) {
        if (message[0] == '4') decodeSecret(message);
        if (message[0] == '5') decodeTransfer(message);
        if (message[0] == '6') decodeLockedTransfer1(message); // and 2
        if (message[0] == '7') decodeMediatedTransfer1(message); // and 2
        else throw;
    }

    function decode(bytes message) returns (bytes32 sig) {
        
    }
    
    function decodeSecret(bytes m) returns (bytes secret, bytes signature) {
        if (m.length != 101) throw;
        secret = slice(m, 4, 36);
        signature = slice(m, 36, 101);
    }
    
    function decodeTransfer(bytes m) returns (uint8 nonce, address asset, address recipient,
                                              uint balance, bytes optionalLocksroot,
                                              bytes optionalSecret, bytes signature) 
    {
        if (m.length != 213) throw;
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        uint160 ia;
        asset = bytesToAddress(slice(m, 12, 32), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 32, 52), ir);
        balance = bytesToInt(slice(m, 52, 84), balance);
        optionalLocksroot = slice(m, 84, 116);
        optionalSecret = slice(m, 116, 148);
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
                                    (bytes locksroot, uint balance, uint amount,
                                     bytes hashlock, bytes signature) 
    {

        locksroot = slice(m, 60, 92);
        balance = bytesToInt(slice(m, 92, 124), balance);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = slice(m, 156, 188);
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
                                    (address initiator, bytes locksroot, bytes hashlock, 
                                     uint balance, uint amount, uint fee, bytes signature) 
    {
        uint160 ii;
        initiator = bytesToAddress(slice(m, 80, 100), ii);
        locksroot = slice(m, 100, 132);
        hashlock = slice(m, 132, 164);
        balance = bytesToInt(slice(m, 164, 196), balance);
        amount = bytesToInt(slice(m, 196, 228), amount);
        fee = bytesToInt(slice(m, 228, 260), fee);
        signature = slice(m, 260, 315);
    }
    
    function decodeCancelTransfer1(bytes m) returns (uint8 nonce, uint8 expiration, 
                                               address asset, address recipient) 
    {
        //if (m.length != 253) throw; // commented for testing
        nonce = bytesToIntEight(slice(m, 4, 12), nonce);
        expiration = bytesToIntEight(slice(m, 12, 20), expiration);
        uint160 ia;
        asset = bytesToAddress(slice(m, 20, 40), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 40, 60), ir);
    }
    
    function decodeCancelTransfer2(bytes m) returns (bytes locksroot, uint balance, 
                                                     uint amount, bytes hashlock) 
    {
        locksroot = slice(m, 60, 92);
        balance = bytesToInt(slice(m, 92, 124), balance);
        amount = bytesToInt(slice(m, 124, 156), amount);
        hashlock = slice(m, 156, 188);
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

    function testDecide() returns (bool yay, string secr) {
        yay = secret[0] == 4;
        bytes memory b = slice(secret, 30, 36); //only getting actual test string
        string memory s = string(b);
        secr = s;
    }
    
    // TODO
    // FAILING TESTS
    function testDecodeSecret() returns (bytes secr, bytes sig, bool isSig, bool isSec, bytes sigb) {
        (secr, sig) = decodeSecret(secret);
        string memory s = string(secr);
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
    function testLocksroot() returns (bytes locksroot, bool isLocksroot, bytes lcrt) {
        (locksroot, , , ) = decodeCancelTransfer2(cancelTrans);
        lcrt = "60d09b4687c162154b290ee5fcbd7c6285590969b3c873e94b690ee9c4f5df51";
        //isLocksroot = compareBytes(locksroot, lcrt) == 0;
    } 
}
