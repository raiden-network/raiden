import "ChannelManagerContract.sol";

contract Registry {
    mapping(address => address) public registry;
    address[] public assets;

    event AssetAdded(address assetAddress);

    modifier addressExists(address _address) {
        if (registry[_address] == 0x0)
            throw;
        _
    }

    modifier doesNotExist(address _address) {
        if (registry[_address] != 0x0)
            throw;
        _
    }

    function addAsset(address assetAddress) doesNotExist(assetAddress) returns (address) {
        address existingAddress;
        address newAddress;
        ChannelManagerContract manager;

        newAddress = new ChannelManagerContract(assetAddress);
        AssetAdded(newAddress);

        registry[assetAddress] = newAddress;
        assets.push(assetAddress);

        return newAddress;
    }

    function channelManagerByAsset(address assetAddress)
        addressExists(assetAddress)
        constant
        returns (address)
    {
        return registry[assetAddress];
    }

    function assetAddresses() constant returns (address[] assetAddresses) {
        return assets;
    }

    function () { throw; }
}
