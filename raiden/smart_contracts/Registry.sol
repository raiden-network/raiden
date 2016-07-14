import "Token.sol";
import "ChannelManagerLibrary.sol";

// for each asset a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;

    ChannelManagerLibrary.Data data;

    function ChannelManagerContract(address tokenAddress) {
        data.token = Token(tokenAddress);
    }

    // XXX: move this to the library, if possible
    // variable length arrays from inside the evm is not supported
    // function getAllChannels() constant returns (address[]) {
    //     return data.getAllChannels();
    // }
    // function getChannelsForNode(address nodeAddress) constant returns (address[]) {
    //     return data.getChannelsForNode(nodeAddress);
    // }
    // function getChannelsParticipants() constant returns (address[]) {
    //     return data.getChannelsParticipants();
    // }
    function getChannelsAddresses() constant returns (address[]) {
        return data.all_channels;
    }

    function getChannelsParticipants() constant returns (address[] channels) {
        uint i;
        uint pos;
        address channel;
        address participant1;
        address participant2;
        address[] memory result;

        result = new address[](data.all_channels.length * 2);

        pos = 0;
        for (i=0; i<data.all_channels.length; i++) {
            channel = data.all_channels[i];

            (participant1, , participant2, ) = NettingChannelContract(channel).addressAndBalance();

            result[pos] = participant1;
            pos += 1;
            result[pos] = participant2;
            pos += 1;
        }

        return result;
    }

    function nettingContractsByAddress(address node_address) constant returns (address[]){
        uint i;
        uint count;
        address channel;
        address participant1;
        address participant2;
        address[] memory result;

        count = 0;
        for (i=0; i<data.all_channels.length; i++) {
            channel = data.all_channels[i];

            (participant1, , participant2, ) = NettingChannelContract(channel).addressAndBalance();

            if (participant1 == node_address) {
                count += 1;
            } else if (participant2 == node_address) {
                count += 1;
            }
        }

        result = new address[](count);
        count -= 1;
        for (i=0; i<data.all_channels.length; i++) {
            channel = data.all_channels[i];

            (participant1, , participant2, ) = NettingChannelContract(channel).addressAndBalance();

            if (participant1 == node_address) {
                result[count] = channel;
                count -= 1;
            } else if (participant2 == node_address) {
                result[count] = channel;
                count -= 1;
            }
        }

        return result;
    }

    function getChannelsForNode(address nodeAddress) constant returns (address[]) {
        return data.nodeChannels[nodeAddress];
    }

    function getChannelWith(address partner) constant returns (address) {
        return data.getChannelWith(partner);
    }

    function newChannel(address partner, uint settleTimeout) returns (address) {
        return data.newChannel(partner, settleTimeout);
    }

    function () { throw; }
}

contract Registry {
    mapping(address => address) public registry;
    address[] public assets;

    event AssetAdded(address assetAddress);

    modifier addressExists(address _address) {
        if (registry[_address] == 0x0)
            throw;
        _
    }

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
