pragma solidity ^0.4.17;

contract Utils {
    string constant public contract_version = "0.3._";

    /// @notice Check if a contract exists
    /// @param contract_address The address to check whether a contract is deployed or not
    /// @return True if a contract exists, false otherwise
    function contractExists(address contract_address) public constant returns (bool) {
        uint size;

        assembly {
            size := extcodesize(contract_address)
        }

        return size > 0;
    }
}
