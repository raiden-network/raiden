import "Token.sol";
import "ChannelManagerLibrary.sol";

// for each asset a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;

    Token public token;
    ChannelManagerLibrary.Data manager;

    function ChannelManagerContract(address tokenAddress) {
        token = Token(tokenAddress);
    }

    // variable length arrays from inside the evm is not supported
    // function getAllChannels() constant returns (address[]) {
    //     return manager.getAllChannels();
    // }
    // function getChannelsForNode(address nodeAddress) constant returns (address[]) {
    //     return manager.getChannelsForNode(nodeAddress);
    // }
    function getAllChannels() constant returns (address[]) {
        return manager.all_channels;
    }

    function getChannelsForNode(address nodeAddress) constant returns (address[]) {
        return manager.node_channels[nodeAddress];
    }

    function getChannelWith(address partner) constant returns (address) {
        return manager.getChannelWith(partner);
    }

    function newChannel(address partner, uint settleTimeout) returns (address) {
        return manager.newChannel(token, partner, settleTimeout);
    }

    function () { throw; }
}

contract Registry {
    mapping(address => address) public registry;
    address[] public assets;

    event AssetAdded(address assetAddress);

    function addAsset(address assetAddress) returns (address) {
        address existingAddress;
        address newAddress;
        ChannelManagerContract manager;

        existingAddress = registry[assetAddress];
        if (existingAddress != 0x0) {
            throw;
        }

        newAddress = new ChannelManagerContract(assetAddress);
        AssetAdded(newAddress);

        registry[assetAddress] = newAddress;
        assets.push(assetAddress);

        return newAddress;
    }

    function channelManagerByAsset(address assetAddress) constant returns (address) {
        return registry[assetAddress];
    }

    function assetAddresses() constant returns (address[] assetAddresses) {
        return assets;
    }

    function () { throw; }
}
