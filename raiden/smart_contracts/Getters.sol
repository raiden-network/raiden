import "Decoder.sol";

contract Getters {
    Decoder public dcdr;

    /*// Get the nonce of the last sent transfer*/
    /*function getNonce(bytes message) private returns (uint8 non) {*/
        /*// Direct Transfer*/
        /*if (message[0] == 5) {*/
            /*(, non, , , , , , ) = dcdr.decodeTransfer(message);*/
        /*}*/
        /*// Locked Transfer*/
        /*if (message[0] == 6) {*/
            /*(non, , , ) = dcdr.decodeLockedTransfer1(message);*/
        /*}*/
        /*// Mediated Transfer*/
        /*if (message[0] == 7) {*/
            /*(non, , , , ) = dcdr.decodeMediatedTransfer1(message); */
        /*}*/
        /*// Cancel Transfer*/
        /*if (message[0] == 8) {*/
            /*(non, , , ) = dcdr.decodeCancelTransfer1(message);*/
        /*}*/
        /*else throw;*/
    /*}*/

    // Gets the sender of a last sent transfer
    function getSender(bytes message) returns (address sndr) {
        // Secret
        if (decideCMD(message) == 4) {
            sndr = dsec(message);
        }
        // Direct Transfer
        if (decideCMD(message) == 5) {
            bytes memory mes = slice(message, 0, 148);
            bytes memory sig = slice(message, 148, 213);
            sndr = ddtran(mes, sig);
        }
        // Locked Transfer
        if (decideCMD(message) == 6) {
            sndr = dltran(message);
        }
        // Mediated Transfer
        if (decideCMD(message) == 7) {
            sndr = dmtran(message);
        }
        // Cancel Transfer
        if (decideCMD(message) == 8) {
            sndr = dctran(message);
        }
        /*else throw;*/
    }

    function decideCMD(bytes message) private returns (uint number) {
        number = uint(message[0]);
    }

    function ecTest(bytes message, bytes sig) returns (address) {
        bytes32 hash = sha3(message);
        var(r, s, v) = dcdr.sigSplit(sig);
        return ecrecover(hash, v, r, s);
    }

    function dsec(bytes message) private returns (address sndr) {
        var(sec, r, s, v) = dcdr.decodeSecret(message);
        bytes32 h = sha3(sec);
        sndr = ecrecover(h, v, r, s);
    }
    function ddtranTEST(bytes message) returns (bytes32 h) {
        var(cmd, non, ass, rec, trn) = dcdr.decodeTransfer1(message);
        var(olo, ops, r, s, v) = dcdr.decodeTransfer2(message);
        h = sha3(cmd, non, ass, rec, trn, olo, ops); //need the optionalLocksroot
    }
    function ddtran(bytes message, bytes sig) private returns (address sndr) {
        bytes32 hash = sha3(message);
        var(r, s, v) = dcdr.sigSplit(sig);
        return ecrecover(hash, v, r, s);
    }
    function dltran(bytes message) private returns (address sndr) {
        bytes32 lock;
        var(non, , ass, rec) = dcdr.decodeLockedTransfer1(message);
        var(loc, bal, , has, r, s, v) = dcdr.decodeLockedTransfer2(message);
        bytes32 h = sha3(non, ass, bal, rec, loc, lock ); //need the lock
        sndr = ecrecover(h, v, r, s);
    }
    function dmtranHelper(bytes message) private returns (bytes32 h) {
        bytes32 lock;
        var(non, , ass, rec, tar, ini, loc) = dcdr.decodeMediatedTransfer1(message); 
        var(bal, fee, , , ) = dcdr.decodeMediatedTransfer2Stripped(message);
        h = sha3(non, ass, bal, rec, loc, lock, tar, ini, fee); //need the lock
    }
    function dmtran(bytes message) private returns (address sndr) {
        bytes32 hash = dmtranHelper(message);
        var(, , , , r, s, v) = dcdr.decodeMediatedTransfer2Stripped(message);
        sndr = ecrecover(hash, v, r, s);
    }
    function dctran(bytes message) private returns (address sndr) {
        bytes32 lock;
        var(non, , ass, rec) = dcdr.decodeCancelTransfer1(message);
        var(loc, bal, , , r, s, v) = dcdr.decodeCancelTransfer2(message);
        bytes32 h = sha3(non, ass, bal, rec, loc, lock); //need the lock
        sndr = ecrecover(h, v, r, s);
    }

    function slice(bytes a, uint start, uint end) private returns (bytes n) {
        if (a.length < end) throw;
        if (start < 0) throw;
        if (start > end) throw;
        n = new bytes(end-start);
        for ( uint i = start; i < end; i ++) { //python style slice
            n[i-start] = a[i];
        }
    }
}
