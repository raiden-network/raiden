pragma solidity ^0.4.17;

import "./Token.sol";
import "./TokenNetwork.sol";

contract TokenNetworkRegistry {

    /*
     *  Data structures
     */

    string constant public contract_version = "0.3._";

    // Token address => TokenNetwork address
    mapping(address => address) public token_to_token_networks;

    /*
     *  Events
     */

    event TokenNetworkCreated(address token_address, address token_network_address);

    /*
     *  External Functions
     */

    function createERC20TokenNetwork(
        address _token_address)
        external
        returns (address token_network_address)
    {
        require(token_to_token_networks[_token_address] == 0x0);

        // Token contract checks are in the corresponding TokenNetwork contract

        token_network_address = new TokenNetwork(_token_address);
        TokenNetworkCreated(_token_address, token_network_address);

        return token_network_address;
    }
}
