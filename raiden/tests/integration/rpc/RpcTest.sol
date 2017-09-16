pragma solidity ^0.4.0;

contract RpcTest {
    function fail() {
        require(false);
    }

    function ret() returns (uint) {
        return 1;
    }
}
