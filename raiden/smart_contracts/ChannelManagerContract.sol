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

    function ChannelManagerContract(address token_address) {
        data.token = Token(token_address);
    }

    function getChannelsParticipants() constant returns (uint channels) {
        return data.total_channels;
    }

    function nettingContractsByAddress(address node_address) constant returns (uint){
        return data.number_of_open_channels[node_address];
    }

    function tokenAddress () constant returns (address) {
        return data.token;
    }

    function getChannelWith(address partner) constant returns (address) {
        return data.getChannelWith(partner);
    }

    function newChannel(address partner, uint settle_timeout) returns (address channel) {
        channel = data.newChannel(partner, settle_timeout);
        ChannelNew(channel, msg.sender, partner, settle_timeout);
    }

    function () { throw; }
}
