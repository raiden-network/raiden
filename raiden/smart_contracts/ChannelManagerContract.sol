pragma solidity ^0.4.0;

import "./Token.sol";
import "./ChannelManagerLibrary.sol";

// for each token a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;
    ChannelManagerLibrary.Data data;
    // All open channels for a specific token
    address[] all_channels;
    // All open channels for a given node
    mapping(address => address[]) node_channels;
    // The two participants of a specific channel
    mapping(address => address[2]) channel_participants;
    // Index of a channel between two parties.
    // This is used to keep track of the position of a partner in `node_channels`
    mapping(address => mapping(address => uint)) node_index;
    // Index of a specific channel in `all_channels`
    mapping(address => uint) all_channels_index;

    event ChannelNew(
        address netting_channel,
        address participant1,
        address participant2,
        uint settle_timeout
    );

    event ChannelDeleted(
        address caller_address,
        address partner
    );

    function ChannelManagerContract(address token_address) {
        data.token = Token(token_address);
    }

    /// @notice Get all channels
    /// @return All the open channels
    function getChannelsAddresses() constant returns (address[] channels) {
        channels = all_channels;
    }

    /// @notice Get all participants of all channels
    /// @return All participants in all channels
    function getChannelsParticipants() constant returns (address[] channels) {
        uint i;
        uint pos;
        address channel;
        address[] memory result;

        result = new address[](all_channels.length * 2);

        pos = 0;
        for (i = 0; i < all_channels.length; i++) {
            channel = all_channels[i];

            result[pos] = channel_participants[channel][0];
            pos += 1;
            result[pos] = channel_participants[channel][1];
            pos += 1;
        }

        return result;
    }

    /// @notice Get all channels that an address participates in.
    /// @param node_address The address of the node
    /// @return The channel's addresses that node_address participates in.
    function nettingContractsByAddress(address node_address) constant returns (address[]) {
        return node_channels[node_address];
    }

    /// @notice Get the address of the channel token
    /// @return The token
    function tokenAddress() constant returns (address) {
        return data.token;
    }

    /// @notice Get the address of channel with a partner
    /// @param partner The address of the partner
    /// @return The address of the channel
    function getChannelWith(address partner) constant returns (address) {
        return data.getChannelWith(partner);
    }

    /// @notice Create a new channel
    /// @param partner The address you want to open a channel with
    /// @param settle_timeout The desired settlement timeout period
    /// @return The address of the newly created channel
    function newChannel(address partner, uint settle_timeout) returns (address channel) {
        address channel_address;

        channel_address = getChannelWith(partner);
        // Check if channel is present in the node_channels mapping within the Data struct
        if (channel_address != 0x0) {
            if (contractExists(channel_address)) {
                throw; // throw if an open contract exists that is not settled
            } else {
                // Delete channel if contract has self destructed
                deleteChannel(partner, channel_address);
            }
        }

        channel = data.newChannel(partner, settle_timeout);

        // Push channel address to array keeping track of all channels
        all_channels.push(channel);
        // Keep track of the index of the channel in the array
        all_channels_index[channel] = all_channels.length - 1;

        // Push channel address to the array keeping track of open channels
        // for msg.sender
        node_channels[msg.sender].push(channel);
        // Keep track of the index of the channel in the array
        node_index[msg.sender][partner] = node_channels[msg.sender].length - 1;

        // Push channel address to the array keeping track of open channels
        // for the partner
        node_channels[partner].push(channel);
        // Keep track of the index of the channel in the array
        node_index[partner][msg.sender] = node_channels[partner].length - 1;

        // add the two participants to the mapping keeping track of all channel participants
        channel_participants[channel] = [msg.sender, partner];

        ChannelNew(channel, msg.sender, partner, settle_timeout);
    }

    /// @notice Check if a contract exists
    /// @param channel The address to check whether a contract is deployed or not
    /// @return True if a contract exists, false otherwise
    function contractExists(address channel) private constant returns (bool) {
        return data.contractExists(channel);
    }

    /// @dev Delete a channel that's been settled
    /// @param partner The address of the partner of the channel
    /// @param channel_address The address to be deleted
    function deleteChannel(address partner, address channel_address) private {
        // throw if the channel has already been deleted
        if (data.getChannelWith(partner) == 0x0) {
            throw;
        }

        address[] our_channels = node_channels[msg.sender];
        address[] partner_channels = node_channels[partner];
        uint caller_index = node_index[msg.sender][partner];
        uint partner_index = node_index[partner][msg.sender];

        // get the last element of the array
        address our_last_element = our_channels[our_channels.length - 1];
        // move the last element to the index of the element to be deleted
        our_channels[caller_index] = our_last_element;
        // decrease the size of the array by one
        our_channels.length--;
        // update the index of the moved element
        node_index[msg.sender][our_last_element] = caller_index;
        // set the index of the deleted element to 0
        // TODO: write test to make sure that setting it to 0 doesn't cause problems
        node_index[msg.sender][partner] = 0;

        // same procedure as above, but just removing the element from the partner array
        address their_last_element = partner_channels[partner_channels.length - 1];
        partner_channels[partner_index] = their_last_element;
        partner_channels.length--;
        node_index[partner][their_last_element] = partner_index;
        node_index[partner][msg.sender] = 0;

        // remove address from all_channels
        // get the index of the channel to me removed
        uint i = all_channels_index[channel_address];
        // set the last element to be at the index of removed element
        all_channels[i] = all_channels[all_channels.length - 1];
        // decrease array length by one
        all_channels.length--;
        // update index of moved element
        all_channels_index[all_channels[i]] = i;
        // set index of deleted element to 0
        all_channels_index[channel_address] = 0;

        node_channels[msg.sender] = our_channels;
        node_channels[partner] = partner_channels;

        data.deleteChannel(partner);
        ChannelDeleted(msg.sender, partner);
    }

    function () { throw; }
}
