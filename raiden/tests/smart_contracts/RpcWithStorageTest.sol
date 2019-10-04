pragma solidity ^0.5.4;

contract RpcWithStorageTest {
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

        data.length = (5 + data.length) ** 2;
        value = data.length;

        for (i=0; i<value; i++) {
            data[i] = value;
        }

        emit RpcEvent(i);
    }

    function waste_storage(uint256 iterations) public {
        uint256 i;
        for (i=0; i<iterations; i++) {
            data[data.length++] = i;
        }
        emit RpcEvent(i);
    }
}
