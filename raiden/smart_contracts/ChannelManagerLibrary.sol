pragma solidity ^0.4.11;

import "./Token.sol";
import "./NettingChannelContract.sol";

library ChannelManagerLibrary {
    string constant public contract_version = "0.2._";

    struct Data {
        Token token;

        address[] all_channels;
        mapping(bytes32 => uint) partyhash_to_channelpos;

        mapping(address => address[]) nodeaddress_to_channeladdresses;
        mapping(address => mapping(address => uint)) node_index;
    }

    /// @notice Create a new payment channel between two parties
    /// @param partner The address of the partner
    /// @param settle_timeout The settle timeout in blocks
    /// @return The address of the newly created NettingChannelContract.
    function newChannel(Data storage self, address partner, uint settle_timeout)
        public
        returns (address)
    {
        address[] storage caller_channels = self.nodeaddress_to_channeladdresses[msg.sender];
        address[] storage partner_channels = self.nodeaddress_to_channeladdresses[partner];

        bytes32 party_hash = partyHash(msg.sender, partner);
        uint channel_pos = self.partyhash_to_channelpos[party_hash];

        address new_channel_address = new NettingChannelContract(
            self.token,
            msg.sender,
            partner,
            settle_timeout
        );

        if (channel_pos != 0) {
            // Check if the channel was settled. Once a channel is settled it
            // kills itself, so address must not have code.
            address settled_channel = self.all_channels[channel_pos - 1];
            require(!contractExists(settled_channel));

            uint caller_pos = self.node_index[msg.sender][partner];
            uint partner_pos = self.node_index[partner][msg.sender];

            // replace the channel address in-place
            self.all_channels[channel_pos - 1] = new_channel_address;
            caller_channels[caller_pos - 1] = new_channel_address;
            partner_channels[partner_pos - 1] = new_channel_address;

        } else {
            self.all_channels.push(new_channel_address);
            caller_channels.push(new_channel_address);
            partner_channels.push(new_channel_address);

            // using the 1-index, 0 is used for the absence of a value
            self.partyhash_to_channelpos[party_hash] = self.all_channels.length;
            self.node_index[msg.sender][partner] = caller_channels.length;
            self.node_index[partner][msg.sender] = partner_channels.length;
        }

        return new_channel_address;
    }

    /// @notice Get the address of channel with a partner
    /// @param partner The address of the partner
    /// @return The address of the channel
    function getChannelWith(Data storage self, address partner)
        public
        constant
        returns (address)
    {
        bytes32 party_hash = partyHash(msg.sender, partner);
        uint channel_pos = self.partyhash_to_channelpos[party_hash];

        if (channel_pos != 0) {
            return self.all_channels[channel_pos - 1];
        }
    }

    /// TODO: Find a way to remove this function duplication from Utils.sol here
    ///       At the moment libraries can't inherit so we need to add this here
    ///       explicitly.
    /// @notice Check if a contract exists
    /// @param channel The address to check whether a contract is deployed or not
    /// @return True if a contract exists, false otherwise
    function contractExists(address channel)
        private
        constant
        returns (bool)
    {
        uint size;

        assembly {
            size := extcodesize(channel)
        }

        return size > 0;
    }

    /// @notice Get the hash of the two addresses
    /// @param address_one address of one party
    /// @param address_two of the other party
    /// @return The keccak256 hash of both parties sorted by size of address
    function partyHash(address address_one, address address_two)
        internal
        pure
        returns (bytes32)
    {
        if (address_one < address_two) {
            return keccak256(address_one, address_two);
        } else {
            // The two participants can't be the same here due to this check in
            // the netting channel constructor:
            // https://github.com/raiden-network/raiden/blob/e17d96db375d31b134ae7b4e2ad2c1f905b47857/raiden/smart_contracts/NettingChannelContract.sol#L27
            return keccak256(address_two, address_one);
        }
    }
}
