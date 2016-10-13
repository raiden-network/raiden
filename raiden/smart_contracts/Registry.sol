pragma solidity ^0.4.0;

import "./ChannelManagerContract.sol";

contract Registry {
    mapping(address => address) public registry;
    address[] public assets;

    event AssetAdded(address assetAddress, address channelManagerAddress);

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

    function addAsset(address assetAddress)
        doesNotExist(assetAddress)
        returns (address)
    {
        address managerAddress;
        ChannelManagerContract manager;

        managerAddress = new ChannelManagerContract(assetAddress);

        registry[assetAddress] = managerAddress;
        assets.push(assetAddress);

        AssetAdded(assetAddress, managerAddress);

        return managerAddress;
    }

    function channelManagerByAsset(address assetAddress)
        addressExists(assetAddress)
        constant
        returns (address)
    {
        return registry[assetAddress];
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
