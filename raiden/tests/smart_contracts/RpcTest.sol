pragma solidity ^0.5.4;

contract RpcTest {
    function fail_require() pure public {
        require(false);
    }

    function fail_assert() pure public {
        assert(false);
    }

    function ret() pure public returns (uint) {
        return 1;
    }

    function ret_str() pure public returns (string memory) {
        return "";
    }

    function loop(uint reps) pure public returns (uint) {
        uint result = 0;
        for (uint i=0; i<reps; i++) {
            result *= i;
        }
        return result;
    }

    event RpcEvent(
        uint _someNumber
    );

    function createEvent(uint _someId) public {
        emit RpcEvent(_someId);
    }
}
