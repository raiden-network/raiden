pragma solidity ^0.6.3;

contract RpcWithStorageTest {
    uint256 current_counter;
    uint256[] data;

    event RpcEvent(
        uint _someNumber
    );

    function get(uint256 _someId) public returns (uint256) {
        return data[_someId];
    }

    function const() public returns (uint256) {
        return 1;
    }

    function gas_increase_exponential() public {
        // This function will use exponentially more storage. Useful to test
        // high variation in gas for consecutive transactions
        uint256 value;
        uint256 i;
        uint256 new_length = (5 + data.length) ** 2;
        for (i=0; i < new_length - data.length ; i++) {
            data.push(new_length);
        }

        emit RpcEvent(i);
    }

    function waste_storage(uint256 iterations) public {
        uint256 i;
        for (i=0; i<iterations; i++) {
            data.push(i);
        }
        emit RpcEvent(i);
    }

    function next(uint256 next_counter, uint256 iterations) public {
        assert(current_counter + 1 == next_counter);

        uint256 i;

        for (i=0; i<iterations; i++) {
            data.push(i);
        }

        current_counter = next_counter;
    }
}
