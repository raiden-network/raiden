import "Token.sol";
import "NettingChannelLibrary.sol";

contract NettingChannelContract {
    NettingChannelLibrary.Data public data;

    function NettingChannelContract(address assetAddress, address participant1, address participant2, uint timeout) {
        if (timeout < 30) {
            timeout = 30;
        }

        data.participants[0].node_address = participant1;
        data.participants[1].node_address = participant2;

        data.token = Token(assetAddress);
        data.settleTimeout = timeout;
    }

    function partner(address ownAddress) constant returns (address) {
    }
}

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => address[]) node_channels;
        address[] all_channels;
    }

    event ChannelNew(
        address nettingChannel,
        address participant1,
        address participant2,
        uint settleTimeout
    );

    function getAllChannels(Data storage self) returns (address[] channels) {
        channels = self.all_channels;
    }

    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @return Array of the channel's addresses that nodeAddress participates.
    function getChannelsForNode(Data storage self, address nodeAddress) constant returns (address[]) {
        return self.node_channels[nodeAddress];
    }

    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @return channel (NettingChannelContract) the value of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner) constant returns (address) {
        uint i;
        address[] our_channels = self.node_channels[msg.sender];
        address channel;

        for (i=0; i < our_channels.length; ++i) {
            channel = our_channels[i];

            if (NettingChannelContract(channel).partner(msg.sender) == partner) {
                return channel;
            }
        }
    }

    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @return NettingChannelContract's address.
    function newChannel(Data storage self, address assetToken, address partner, uint settleTimeout) returns (address) {
        address channelAddress;

        channelAddress = new NettingChannelContract(
            assetToken,
            msg.sender,
            partner,
            settleTimeout
        );
        ChannelNew(
            channelAddress,
            msg.sender,
            partner,
            settleTimeout
        );

        self.node_channels[msg.sender].push(channelAddress);
        self.node_channels[partner].push(channelAddress);
        self.all_channels.push(channelAddress);

    }
}
