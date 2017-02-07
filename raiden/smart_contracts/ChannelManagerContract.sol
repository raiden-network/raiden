pragma solidity ^0.4.0;

import "./Token.sol";
import "./ChannelManagerLibrary.sol";

// for each asset a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;
    ChannelManagerLibrary.Data data;
    address[] all_channels;
    mapping(address => address[]) node_channels;
    mapping(address => address[2]) channel_participants;
    mapping(address => mapping(address => uint)) node_index;
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

    /// @notice getChannelsAddresses to get all channels
    /// @dev Get all channels
    /// @return all the open channels
    function getChannelsAddresses() constant returns (address[] channels) {
        channels = all_channels;
    }

    function getChannelsParticipants() constant returns (address[] channels) {
        uint i;
        uint pos;
        address channel;
        address participant1;
        address participant2;
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

    /// @notice nettingContractsByAddress to get channels that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param node_address The address of the node
    /// @return The channel's addresses that node_address participates in.
    function nettingContractsByAddress(address node_address) constant returns (address[]){
        return node_channels[node_address];
    }

    function tokenAddress() constant returns (address) {
        return data.token;
    }

    function getChannelWith(address partner) constant returns (address) {
        return data.getChannelWith(msg.sender, partner);
    }

    function newChannel(address partner, uint settle_timeout) returns (address channel) {
        address channel_address;

        channel_address = getChannelWith(partner);
        // Check if channel is present in the node_channels mapping within the Data struct
        if (channel_address != 0x0) {
            if (contractExists(channel_address)) {
                throw; // throw if an open contract exists that is not settled
            } else {
                // Delete channel if contract has self destructed
                deleteChannel(msg.sender, partner, channel_address);
            }
        }

        channel = data.newChannel(msg.sender, partner, settle_timeout);

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

        // add the two participants to mapping keeping track of all channel participants
        channel_participants[channel] = [msg.sender, partner];

        ChannelNew(channel, msg.sender, partner, settle_timeout);
    }

    function contractExists(address channel) private constant returns (bool) {
        return data.contractExists(channel);
    }

    function deleteChannel(
        address caller_address,
        address partner,
        address channel_address)
        private
    {
        address[] our_channels = node_channels[caller_address];
        address[] partner_channels = node_channels[partner];
        uint caller_index = node_index[caller_address][partner];
        uint partner_index = node_index[partner][caller_address];

        // get the last element of the array
        address our_last_element = our_channels[our_channels.length - 1];
        // move the last element to the index of the element to be deleted
        our_channels[caller_index] = our_last_element;
        // decrease the size of the array by one
        our_channels.length--;
        // update the index of the moved element
        node_index[caller_address][our_last_element] = caller_index;
        // set the index of the deleted element to 0
        // TODO: write test to make sure that setting it to 0 doesn't cause problems
        node_index[caller_address][partner] = 0;

        // same procedure as above, but just removing the element from the partner array
        address their_last_element = partner_channels[partner_channels.length - 1];
        partner_channels[partner_index] = their_last_element;
        partner_channels.length--;
        node_index[partner][their_last_element] = partner_index;
        node_index[partner][caller_address] = 0;

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

        node_channels[caller_address] = our_channels;
        node_channels[partner] = partner_channels;

        data.deleteChannel(caller_address, partner);
        ChannelDeleted(caller_address, partner);
    }

    function () { throw; }
}
