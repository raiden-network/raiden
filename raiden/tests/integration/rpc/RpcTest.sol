pragma solidity ^0.4.0;

contract RpcTest {
    function fail() {
        require(false);
    }

    function ret() returns (uint) {
        return 1;
    }

    function loop(uint reps) returns (uint) {
        uint result = 0;
        for (uint i=0; i<reps; i++) {
            result *= i;
        }
        return result;
    }
}
