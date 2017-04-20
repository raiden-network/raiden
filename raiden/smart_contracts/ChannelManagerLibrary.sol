pragma solidity ^0.4.0;

import "./Token.sol";
import "./NettingChannelContract.sol";

library ChannelManagerLibrary {
    struct Data {
        mapping(bytes32 => address) channel_addresses;
        Token token;
    }

    /// @notice Get the address of the unique channel of two parties.
    /// @param partner The address of the partner
    /// @return The address of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner)
        constant
        returns (address)
    {
        bytes32 party_hash = partyHash(msg.sender, partner);
        return self.channel_addresses[party_hash];
    }

    /// @notice Create a new payment channel between two parties
    /// @param partner The address of the partner
    /// @param settle_timeout The settle timeout in blocks
    /// @return The address of the NettingChannelContract.
    function newChannel(
        Data storage self,
        address partner,
        uint settle_timeout)
        returns (address channel_address)
    {
        channel_address = new NettingChannelContract(
            self.token,
            msg.sender,
            partner,
            settle_timeout
        );

        self.channel_addresses[partyHash(msg.sender, partner)] = channel_address;
    }

    /// @notice Remove a channel after it's been settled
    /// @param partner of the partner
    function deleteChannel(Data storage self, address partner) internal
    {
        // remove channel from channel_addresses.
        self.channel_addresses[partyHash(msg.sender, partner)] = 0x0;
    }

    /// @notice Get the hash of the two addresses
    /// @param address_one address of one party
    /// @param address_two of the other party
    /// @return The sha3 hash of both parties sorted by size of address
    function partyHash(address address_one, address address_two) private constant returns (bytes32) {
        if (address_one < address_two) {
            return sha3(address_one, address_two);
        } else if (address_one > address_two){
            return sha3(address_two, address_one);
        } else {
            throw; // if the two addresses provided are identical
        }
    }

    /// @notice Check if a contract is deployed at given address
    /// @param _addr address to check for a deployed contract
    /// @return if contract exists, false if not
    function contractExists(Data storage self, address _addr) internal constant returns (bool) {
        uint size;
        assembly {
            size := extcodesize(_addr)
        }
        if (size > 0) {
            return true;
        }
    }
}
