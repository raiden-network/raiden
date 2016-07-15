import "Token.sol";
import "NettingChannelContract.sol";

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => address[]) nodeChannels;
        address[] all_channels;
        Token token;
    }

    function getChannelsAddresses(Data storage self) returns (address[] channels) {
        channels = self.all_channels;
    }

    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @return Array of the channel's addresses that nodeAddress participates.
    function getChannelsForNode(Data storage self, address nodeAddress) constant returns (address[]) {
        return self.nodeChannels[nodeAddress];
    }

    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @return channel (NettingChannelContract) the value of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner) constant returns (address) {
        uint i;
        address[] our_channels = self.nodeChannels[msg.sender];
        address channel;

        for (i=0; i < our_channels.length; ++i) {
            channel = our_channels[i];

            if (NettingChannelContract(channel).partner(msg.sender) == partner) {
                return channel;
            }
        }

        throw;
    }

    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @return NettingChannelContract's address.
    function newChannel(Data storage self, address partner, uint settleTimeout) returns (address) {
        address channelAddress;
        uint i;

        address[] storage existingChannels = self.nodeChannels[msg.sender];
        for (i=0; i<existingChannels.length; i++) {
            if (NettingChannelContract(existingChannels[i]).partner(msg.sender) == partner) {
                throw;
            }
        }

        channelAddress = new NettingChannelContract(
            self.token,
            msg.sender,
            partner,
            settleTimeout
        );

        self.nodeChannels[msg.sender].push(channelAddress);
        self.nodeChannels[partner].push(channelAddress);
        self.all_channels.push(channelAddress);

        return channelAddress;
    }
}
