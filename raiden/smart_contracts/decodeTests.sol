contract decodeTest {
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
