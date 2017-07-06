pragma solidity ^0.4.0;

import "./ChannelManagerContract.sol";

contract Registry {
    mapping(address => address) public registry;
    address[] public tokens;

    event TokenAdded(address token_address, address channel_manager_address);

    modifier addressExists(address _address) {
        if (registry[_address] == 0x0)
            throw;
        _;
    }

    modifier doesNotExist(address _address) {
        if (registry[_address] != 0x0)
            throw;
        _;
    }

    /// @notice Register a new ERC20 token
    /// @param token_address Address of the token
    /// @return The address of the channel manager
    function addToken(address token_address)
        doesNotExist(token_address)
        returns (address)
    {
        address manager_address;

        manager_address = new ChannelManagerContract(token_address);

        registry[token_address] = manager_address;
        tokens.push(token_address);

        TokenAdded(token_address, manager_address);

        return manager_address;
    }

    /// @notice Get the ChannelManager address for a specific token
    /// @param token_address The address of the given token
    /// @return Address of channel manager
    function channelManagerByToken(address token_address)
        addressExists(token_address)
        constant
        returns (address)
    {
        return registry[token_address];
    }

    /// @notice Get all registered tokens
    /// @return addresses of all registered tokens
    function tokenAddresses()
        constant
        returns (address[])
    {
        return tokens;
    }

    /// @notice Get the addresses of all channel managers for all registered tokens
    /// @return addresses of all channel managers
    function channelManagerAddresses()
        constant
        returns (address[])
    {
        uint i;
        address token_address;
        address[] memory result;

        result = new address[](tokens.length);

        for (i = 0; i < tokens.length; i++) {
            token_address = tokens[i];
            result[i] = registry[token_address];
        }

        return result;
    }

    function () { throw; }
}
