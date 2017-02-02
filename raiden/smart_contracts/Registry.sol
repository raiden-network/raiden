pragma solidity ^0.4.0;

import "./ChannelManagerContract.sol";

contract Registry {
    mapping(address => address) public registry;
    address[] public assets;

    event AssetAdded(address asset_address, address channel_manager_address);

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

    /// @notice addAsset(address) to register a new ERC20 token
    /// @dev Register a new ERC20 token
    /// @param asset_address (address) the address of the token
    /// @return (address) the address of the channel manager
    function addAsset(address asset_address)
        doesNotExist(asset_address)
        returns (address)
    {
        address manager_address;
        ChannelManagerContract manager;

        manager_address = new ChannelManagerContract(asset_address);

        registry[asset_address] = manager_address;
        assets.push(asset_address);

        AssetAdded(asset_address, manager_address);

        return manager_address;
    }

    /// @notice channelManagerByAsset(address) to get the ChannelManager address for a specific token
    /// @dev get the address of the channel manager for the given token
    /// @param asset_address (address) the address of the given token
    /// @return (address) address of channel manager
    function channelManagerByAsset(address asset_address)
        addressExists(asset_address)
        constant
        returns (address)
    {
        return registry[asset_address];
    }

    /// @notice assetAddresses() to get all registered tokens
    /// @dev Get all registered tokens
    /// @return (address[]) addresses of all registered tokens
    function assetAddresses()
        constant
        returns (address[])
    {
        return assets;
    }

    /// @notice channelManagerAddresses() to get the addresses of all channel managers for all registered tokens
    /// @dev Get all addresses for channel managers
    /// @return (address[]) addresses of all channel managers
    function channelManagerAddresses()
        constant
        returns (address[])
    {
        uint i;
        address asset_address;
        address[] memory result;

        result = new address[](assets.length);

        for (i = 0; i < assets.length; i++) {
            asset_address = assets[i];
            result[i] = registry[asset_address];
        }

        return result;
    }

    function () { throw; }
}
