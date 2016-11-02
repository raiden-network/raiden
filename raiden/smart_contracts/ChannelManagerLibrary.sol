pragma solidity ^0.4.0;

import "./Token.sol";
import "./NettingChannelContract.sol";

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => address[]) node_channels;
        address[] all_channels;
        Token token;
    }

    /// @notice getChannelsAddresses to get all channels
    /// @dev Get all channels
    /// @return channels (address[]) all the channels
    function getChannelsAddresses(Data storage self) returns (address[] channels) {
        channels = self.all_channels;
    }

    /// @notice getChannelsForNode(address) to get channels that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param node_address (address) the address of the node
    /// @return (address[]) of the channel's addresses that node_address participates.
    function getChannelsForNode(Data storage self, address node_address)
        constant
        returns (address[])
    {
        return self.node_channels[node_address];
    }

    /// @notice getChannelWith(address) to get the address of the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param partner (address) the address of the partner
    /// @return channel (address) the address of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner)
        constant
        returns (address)
    {
        uint i;
        address[] our_channels = self.node_channels[msg.sender];
        address channel;

        for (i = 0; i < our_channels.length; ++i) {
            channel = our_channels[i];

            if (NettingChannelContract(channel).partner(msg.sender) == partner) {
                return channel;
            }
        }

        throw;
    }

    /// @notice newChannel(address, uint) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @param partner (address) the address of the partner
    /// @param settle_timeout (uint) the settle timeout in blocks
    /// @return (address) the address of the NettingChannelContract.
    function newChannel(
        Data storage self,
        address partner,
        uint settle_timeout)
        returns (address)
    {
        address channel_address;
        uint i;

        address[] storage existing_channels = self.node_channels[msg.sender];
        for (i = 0; i < existing_channels.length; i++) {
            if (NettingChannelContract(existing_channels[i]).partner(msg.sender) == partner) {
                throw;
            }
        }

        channel_address = new NettingChannelContract(
            self.token,
            msg.sender,
            partner,
            settle_timeout
        );

        self.node_channels[msg.sender].push(channel_address);
        self.node_channels[partner].push(channel_address);
        self.all_channels.push(channel_address);

        return channel_address;
    }
}
