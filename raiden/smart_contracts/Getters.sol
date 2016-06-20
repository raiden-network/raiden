import "Decoder.sol";

contract Getters {
    Decoder public dcdr;

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

    function sigSplit(bytes message) returns (bytes32 r, bytes32 s, uint8 v) {
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

    // Function for ECRecovery
    function ecRec(bytes message, bytes sig) private returns (address sndr) {
        bytes32 hash = sha3(message);
        var(r, s, v) = sigSplit(sig);
        sndr = ecrecover(hash, v, r, s);
    }

    function decideCMD(bytes message) private returns (uint number) {
        number = uint(message[0]);
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
