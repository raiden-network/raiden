pragma solidity ^0.4.11;

import "./Token.sol";
import "./ChannelManagerLibrary.sol";

// for each token a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;
    ChannelManagerLibrary.Data data;

    address[] all_channels;
    mapping(address => address[]) node_channels;

    // These two mappings keep track of the channel address position within the
    // all_channels and node_channels arrays, the values are used to update the
    // addresses once a new channel is opened.
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

    /// @notice Get all channels
    /// @return All the open channels
    function getChannelsAddresses() constant returns (address[]) {
        return all_channels;
    }

    /// @notice Get all participants of all channels
    /// @return All participants in all channels
    function getChannelsParticipants() constant returns (address[]) {
        uint i;
        uint pos;
        address[] memory result;
        NettingChannelContract channel;

        result = new address[](all_channels.length * 2);

        pos = 0;
        for (i = 0; i < all_channels.length; i++) {
            channel = NettingChannelContract(all_channels[i]);

            var (address1, , address2, ) = channel.addressAndBalance();

            result[pos] = address1;
            pos += 1;
            result[pos] = address2;
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
    function newChannel(address partner, uint settle_timeout) returns (address) {
        address settled_channel = getChannelWith(partner);
        address[] storage caller_channels = node_channels[msg.sender];
        address[] storage partner_channels = node_channels[partner];

        if (settled_channel != 0) {
            // Checking the channel was settled indirectly. Once the channel is
            // settled it kill itself, so address must not have code.
            require(!contractExists(settled_channel));
            ChannelDeleted(msg.sender, partner);
        }

        address new_channel = data.newChannel(partner, settle_timeout);

        // replace the channel address in-place
        if (settled_channel != 0) {
            uint channels_idx = all_channels_index[settled_channel];
            uint caller_idx = node_index[msg.sender][partner];
            uint partner_idx = node_index[partner][msg.sender];

            all_channels[channels_idx] = new_channel;
            caller_channels[caller_idx] = new_channel;
            partner_channels[partner_idx] = new_channel;

        // first channel open among the participants, create a new entry
        } else {
            all_channels.push(new_channel);
            caller_channels.push(new_channel);
            partner_channels.push(new_channel);

            all_channels_index[new_channel] = all_channels.length - 1;
            node_index[msg.sender][partner] = caller_channels.length - 1;
            node_index[partner][msg.sender] = partner_channels.length - 1;
        }

        ChannelNew(new_channel, msg.sender, partner, settle_timeout);
        return new_channel;
    }

    /// @notice Check if a contract exists
    /// @param channel The address to check whether a contract is deployed or not
    /// @return True if a contract exists, false otherwise
    function contractExists(address channel) private constant returns (bool) {
        uint size;

        assembly {
            size := extcodesize(channel)
        }

        if (size > 0) {
            return true;
        }

        return false;
    }

    function () { revert(); }
}
