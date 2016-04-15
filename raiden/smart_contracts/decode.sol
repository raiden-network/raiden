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
        //if (message[0] == '7') decodeMediatedTransfer(message);
        else throw;
    }
    
    function decode(bytes message) returns (bytes32 sig) {
        
    }
    
    function decodeSecret(bytes m) returns (bytes secret, bytes signature) {
        secret = slice(m, 4, 36);
        signature = slice(m, 36, 101);
    }
    
    function decodeTransfer(bytes m) returns (uint nonce, address asset, address recipient,
                                              uint balance, bytes optionalLocksroot,
                                              bytes optionalSecret, bytes signature) 
    {
        nonce = bytesToInt(slice(m, 4, 12), nonce);
        uint160 ia;
        asset = bytesToAddress(slice(m, 12, 32), ia);
        uint160 ir;
        recipient = bytesToAddress(slice(m, 32, 52), ir);
        balance = bytesToInt(slice(m, 52, 84), balance);
        optionalLocksroot = slice(m, 84, 116);
        optionalSecret = slice(m, 116, 148);
        signature = slice(m, 148, 213);
    }
    
    function decodeLockedTransfer1(bytes m) returns (uint nonce, uint expiration, 
                                                     address asset, address recipient) 
    {
        nonce = bytesToInt(slice(m, 4, 12), nonce);
        expiration = bytesToInt(slice(m, 12, 20), expiration);
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
    
    function decodeMediatedTransfer1(bytes m) returns (uint nonce, uint expiration, 
                                                       address asset, address recipient,
                                                       address target) 
    {
        nonce = bytesToInt(slice(m, 4, 12), nonce);
        expiration = bytesToInt(slice(m, 12, 20), expiration);
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
    
    function bytesToInt(bytes b, uint i) returns (uint res) {
        assembly { i := mload(add(b, 0x20)) }
    }
    
    function bytesToAddress(bytes b, uint160 i) returns (address add) {
        assembly { i := mload(add(b, 0x20)) }
        add = address(i);
    }
    
    function testDecode() returns (bool yay) {
        string memory t = decideCmd('6');
        //yay = compareStrings(t, "LOCKEDTRANSFER") == 0;
    }
}
