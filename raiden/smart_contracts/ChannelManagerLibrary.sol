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
            if (!contractExists(self, existing_channels[i])) {
                // delete all channels that has been settled
                // settled contracts will commit suicide and thus not exist on their address
                deleteChannel(self, partner, existing_channels[i]);
            } else if (NettingChannelContract(existing_channels[i]).partner(msg.sender) == partner) {
                // throw if an open contract exists that is not settled
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

    /// @notice deleteChannel(address) to remove a channel after it's been settled
    /// @dev Remove channel after it's been settled
    /// @param channel_address (address) address of the channel to be closed
    /// @param partner (address) address of the partner
    function deleteChannel(Data storage self, address partner, address channel_address) private {

        address[] our_channels = self.node_channels[msg.sender];
        address[] partner_channels = self.node_channels[partner];

        // remove element from sender
        for (uint i = 0; i < our_channels.length; ++i) {
            if (our_channels[i] == channel_address) {
                our_channels[i] = our_channels[our_channels.length - 1];
                our_channels.length--;
                break;
            }
        }

        // remove element from partner
        for (uint j = 0; j < partner_channels.length; ++j) {
            if (partner_channels[j] == channel_address) {
                partner_channels[j] = partner_channels[partner_channels.length - 1];
                partner_channels.length--;
                break;
            }
        }

        // remove address from all_channels
        for (uint k = 0; k < self.all_channels.length; ++k) {
            if (self.all_channels[k] == channel_address) {
                self.all_channels[k] == self.all_channels[self.all_channels.length - 1];
                self.all_channels.length--;
                break;
            }
        }

        self.node_channels[msg.sender] = our_channels;
        self.node_channels[partner] = partner_channels;
    }

    /// @notice contractExists(address) to check if a contract is deployed at given address
    /// @dev Check if a channel is deployed at address
    /// @param _addr (address) the address to check for a deployed contract
    /// @return (bool) true if contract exists, false if not
    function contractExists(Data storage self, address _addr) returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        if (size > 0) return true;
    }
}
