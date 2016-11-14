pragma solidity ^0.4.0;

import "./Token.sol";
import "./NettingChannelContract.sol";

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => mapping(address => bool)) channels;
        mapping(address => mapping(address => address)) channel_addresses;
        uint total_channels;
        mapping(address => uint) number_of_open_channels;
        Token token;
    }

    /// @notice getChannelWith(address) to get the address of the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param partner (address) the address of the partner
    /// @return channel (address) the address of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner)
        constant
        returns (address)
    {
        if(!self.channels[msg.sender][partner]) {
            throw;
        }
        return self.channel_addresses[msg.sender][partner];
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
        if (self.channels[msg.sender][partner]) {
            throw;
        }

        address channel_address;

        channel_address = new NettingChannelContract(
            self.token,
            msg.sender,
            partner,
            settle_timeout
        );

        self.channels[msg.sender][partner] = true;
        self.channels[partner][msg.sender] = true;
        self.channel_addresses[msg.sender][partner] = channel_address;
        self.channel_addresses[partner][msg.sender] = channel_address;
        self.number_of_open_channels[msg.sender]++;
        self.number_of_open_channels[partner]++;
        self.total_channels++;

        return channel_address;
    }
}
