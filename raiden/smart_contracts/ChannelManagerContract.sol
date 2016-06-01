import "IterableMappingNCC.sol";
contract ChannelManagerContract {
    IterableMappingNCC.itmap data;

    address public assetAddress;

    // Events
    // Event that triggers when a new channel is created
    // Gives the created channel
    event ChannelNew(address partner);// update to use both addresses

    // Initialize the Contract
    /// @notice ChannelManagerContract(address) to contruct the contract
    /// @dev Initiate the contract with the constructor
    /// @param assetAdr (address) the address of an asset
    function ChannelManagerContract(address assetAdr) {
        assetAddress = assetAdr;
    }

    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param adr (address) the address
    /// @return channels (NettingChannelContracts[]) all channels that a given address participates in.
    function nettingContractsByAddress(address adr) returns (NettingChannelContract[] channels){
        channels = new NettingChannelContract[](numberOfItems(adr));
        uint idx = 0;
        for (var i = IterableMappingNCC.iterate_start(data); IterableMappingNCC.iterate_valid(data, i); i = IterableMappingNCC.iterate_next(data, i)) {
            var (key, value) = IterableMappingNCC.iterate_get(data, i);
            var(addr1,) = value.participants(0); // TODO: find more elegant way to do this
            var(addr2,) = value.participants(1); // TODO: find more elegant way to do this
            if (addr1 == adr) {
                channels[idx] = value;
                idx++;
            }
            else if (addr2 == adr) {
                channels[idx] = value;
                idx++;
            }
        }
    }

    /// @notice numberOfItems(address) to get the number of times a given address participates 
    /// in a channel.
    /// @dev get amount of times an address participates in a channel
    /// @param adr (address) adress to look for
    /// @return items (uint) amount of channels an address participates in
    function numberOfItems(address adr) private returns (uint items) {
        items = 0;
        for (var i = IterableMappingNCC.iterate_start(data); IterableMappingNCC.iterate_valid(data, i); i = IterableMappingNCC.iterate_next(data, i)) {
            var(key, value) = IterableMappingNCC.iterate_get(data, i);
            var(addr1,) = value.participants(0); // TODO: find more elegant way to do this
            var(addr2,) = value.participants(1); // TODO: find more elegant way to do this
            if (addr1 == adr) {
                items++;
            }
            else if (addr2 == adr) {
                items++;
            }
        }
    }

    /// @notice getAllChannels() to return a list of all existing channels
    /// @dev return a list of all existing channels
    /// @return addresses (address[]) list of all addresses in the channel 
    /// index 0 and 1 is a pair, index 2 and 3 is a pair etc.
    // TODO use array of pairs
    function getAllChannels() returns (address[] addresses) {
        uint idx = 0;
        addresses = new address[](data.size * 2);
        for (var i = IterableMappingNCC.iterate_start(data); IterableMappingNCC.iterate_valid(data, i); i = IterableMappingNCC.iterate_next(data, i)) {
            var(, v) = IterableMappingNCC.iterate_get(data, i);
            // add first address
            var(addr1, ) = v.participants(0);
            addresses[idx] = addr1;
            // increment index
            idx++;
            // add second address
            var(addr2, ) = v.participants(1);
            addresses[idx] = addr2;
            // increment the index for next channel
            idx++;
        }
    }

    /// @notice key(address, address) to create a key of the two addressed.
    /// @dev Get a hashed key of two addresses.
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return key (bytes32) sha3 hash of the two keys.
    function key(address adrA, address adrB) private returns (bytes32 key){
        if (adrA == adrB) throw;
        if (adrA < adrB) return sha3(adrA, adrB);
        else return sha3(adrB, adrA);
    }

    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return channel (NettingChannelContract) the value of the NettingChannelContract of the two parties.
    function get(address adrA, address adrB) returns (NettingChannelContract channel){
        bytes32 ky = key(adrA, adrB);
        if (IterableMappingNCC.contains(data, ky) == false) throw; //handle if no such channel exists
        uint index = IterableMappingNCC.atIndex(data, ky);
        var (k, v) = IterableMappingNCC.iterate_get(data, index - 1); // -1 ?
        channel = v;
    }

    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @param partner (address) address of one partner
    /// @return channel (NettingChannelContract) the NettingChannelContract of the two parties.
    function newChannel(address partner, uint lckdTime) returns (NettingChannelContract c, address sender){
        bytes32 k = key(msg.sender, partner);
        if (IterableMappingNCC.contains(data, k)) throw;
        IterableMappingNCC.insert(data, k, assetAddress, msg.sender, partner, lckdTime);
        sender = msg.sender; // Only for testing purpose, should not be added to live net
        ChannelNew(partner); //Triggers event
    }

    // empty function to handle wrong calls
    function () { throw; }
}
