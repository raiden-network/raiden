pragma solidity ^0.4.0;

import "./Token.sol";
import "./ChannelManagerLibrary.sol";

// for each asset a manager will be deployed, to reduce gas usage for manager
// deployment the logic is moved into a library and this contract will work
// only as a proxy/state container.
contract ChannelManagerContract {
    using ChannelManagerLibrary for ChannelManagerLibrary.Data;
    ChannelManagerLibrary.Data data;

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
        for (i = 0; i < data.all_channels.length; i++) {
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
        for (i = 0; i < data.all_channels.length; i++) {
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

    function tokenAddress () constant returns (address) {
        return data.token;
    }

    function getChannelsForNode(address node_address) constant returns (address[]) {
        return data.node_channels[node_address];
    }

    function getChannelWith(address partner) constant returns (address, bool, uint, uint) {
        return data.getChannelWith(msg.sender, partner);
    }

    function newChannel(address partner, uint settle_timeout) returns (address channel) {
        address channel_address;
        bool has_channel;
        uint caller_index;
        uint partner_index;

        (channel_address, has_channel, caller_index, partner_index) = getChannelWith(partner);
        // Check if channel is present in the node_channels mapping within the Data struct
        if (has_channel) {
            if (contractExists(channel_address)) {
                throw; // throw if an open contract exists that is not settled
            } else {
                // If contract is not deployed(mostly committed suicide) only then call deleteChannel
                deleteChannel(msg.sender, partner, channel_address, caller_index, partner_index);
            }
        }

        channel = data.newChannel(msg.sender, partner, settle_timeout);
        ChannelNew(channel, msg.sender, partner, settle_timeout);
    }

    function contractExists(address channel) returns (bool) {
        return data.contractExists(channel);
    }

    function deleteChannel(
        address caller_address,
        address partner,
        address channel_address,
        uint caller_index,
        uint partner_index)
    {
        data.deleteChannel(caller_address, partner, channel_address, caller_index, partner_index);
        ChannelDeleted(caller_address, partner);
    }

    function () { throw; }
}
