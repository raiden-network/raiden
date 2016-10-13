pragma solidity ^0.4.0;

import "./Token.sol";
import "./NettingChannelContract.sol";

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => address[]) nodeChannels;
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
    /// @param nodeAddress (address) the address of the node
    /// @return (address[]) of the channel's addresses that nodeAddress participates.
    function getChannelsForNode(Data storage self, address nodeAddress) constant returns (address[]) {
        return self.nodeChannels[nodeAddress];
    }

    /// @notice getChannelWith(address) to get the address of the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param partner (address) the address of the partner
    /// @return channel (address) the address of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner) constant returns (address) {
        uint i;
        address[] our_channels = self.nodeChannels[msg.sender];
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
    /// @param settleTimeout (uint) the settleTimeout in blocks
    /// @return (address) the address of the NettingChannelContract.
    function newChannel(Data storage self, address partner, uint settleTimeout) returns (address) {
        address channelAddress;
        uint i;

        address[] storage existingChannels = self.nodeChannels[msg.sender];
        for (i = 0; i < existingChannels.length; i++) {
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
