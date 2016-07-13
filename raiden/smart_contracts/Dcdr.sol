library Dcdr {
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
        if (m.length != 72) throw;
        expiration = bytesToIntEight(slice(m, 0, 8), expiration);
        amount = bytesToInt(slice(m, 8, 40), amount);
        hashlock = bytesToBytes32(slice(m, 40, 72), hashlock);
    }

    /*// Gets the sender of a last sent transfer*/
    /*function getSender(bytes message) returns (address sndr) {*/
        /*bytes memory mes;*/
        /*bytes memory sig;*/
        /*// Secret*/
        /*if (decideCMD(message) == 4) {*/
            /*mes = slice(message, 0, 36);*/
            /*sig = slice(message, 36, 101);*/
            /*sndr = ecRec(mes, sig);*/
        /*}*/
        /*// Direct Transfer*/
        /*if (decideCMD(message) == 5) {*/
            /*mes = slice(message, 0, 148);*/
            /*sig = slice(message, 148, 213);*/
            /*sndr = ecRec(mes, sig);*/
        /*}*/
        /*// Locked Transfer*/
        /*if (decideCMD(message) == 6) {*/
            /*mes = slice(message, 0, 188);*/
            /*sig = slice(message, 188, 253);*/
            /*sndr = ecRec(mes, sig);*/
        /*}*/
        /*// Mediated Transfer*/
        /*if (decideCMD(message) == 7) {*/
            /*mes = slice(message, 0, 260);*/
            /*sig = slice(message, 260, 325);*/
            /*sndr = ecRec(mes, sig);*/
        /*}*/
        /*// Cancel Transfer*/
        /*if (decideCMD(message) == 8) {*/
            /*mes = slice(message, 0, 188);*/
            /*sig = slice(message, 188, 253);*/
            /*sndr = ecRec(mes, sig);*/
        /*}*/
        /*[>else throw;<]*/
    /*}*/

    /*// Function for ECRecovery*/
    /*function ecRec(bytes message, bytes sig) private returns (address sndr) {*/
        /*bytes32 hash = sha3(message);*/
        /*var(r, s, v) = sigSplit(sig);*/
        /*sndr = ecrecover(hash, v, r, s);*/
    /*}*/

     /*[>HELPER FUNCTIONS <]*/
    /*function sigSplit(bytes message) private returns (bytes32 r, bytes32 s, uint8 v) {*/
        /*if (message.length != 65) throw;*/

        /*// The signature format is a compact form of:*/
        /*//   {bytes32 r}{bytes32 s}{uint8 v}*/
        /*// Compact means, uint8 is not padded to 32 bytes.*/
        /*assembly {*/
            /*r := mload(add(message, 32))*/
            /*s := mload(add(message, 64))*/
            /*// Here we are loading the last 32 bytes, including 31 bytes*/
            /*// of 's'. There is no 'mload8' to do this.*/
            /*//*/
            /*// 'byte' is not working due to the Solidity parser, so lets*/
            /*// use the second best option, 'and'*/
            /*v := and(mload(add(message, 65)), 1)*/

        /*}*/
        /*// old geth sends a `v` value of [0,1], while the new, in line with the YP sends [27,28]*/
        /*if(v < 27) v += 27;*/
    /*}*/

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

    function decideCMD(bytes message) private returns (uint number) {
        number = uint(message[0]);
    }
    // empty function to handle wrong calls
    function () { throw; }
}
