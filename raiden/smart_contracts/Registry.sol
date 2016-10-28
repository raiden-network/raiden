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

    function channelManagerByAsset(address asset_address)
        addressExists(asset_address)
        constant
        returns (address)
    {
        return registry[asset_address];
    }

    function assetAddresses()
        constant
        returns (address[])
    {
        return assets;
    }

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
