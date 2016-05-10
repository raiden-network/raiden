import slice.sol as slice;

library Decoder {
    
    // Slice helper function
    // TODO Should be replaced by slice.slb 
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
        if (m.length != 325) throw;
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
        uint160 a = uint160(i); // check if this is needed
        add = address(i);
    }
    
    function bytesToBytes32(bytes b, bytes32 i) returns (bytes32 bts) {
        assembly { i := mload(add(b, 0x20)) }
        bts = i;
    }
}
