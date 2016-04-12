import "nccItSet.sol";

contract ChannelManagerContract {

    IterableMappingNcc.itmap data;

    address assetAddress;

    // Events
    // Event that triggers when a new channel is created
    // Gives the created channel
    event ChannelNew(NettingContract channel);

    // Initialize the Contract
    /// @notice ChannelManagerContract(address) to contruct the contract
    /// @dev Initiate the contract with the constructor
    /// @param assetAddress (address) the address of an asset
    function ChannelManagerContract(address assetAdr) {
        assetAddress = assetAdr;
    }


    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param adr (address) the address
    /// @return channels (NettingContracts[]) all channels that a given address participates in.
    function nettingContractsByAddress(address adr) returns (NettingContract[] channels){
        for (var i = IterableMappingNcc.iterate_start(data); IterableMappingNcc.iterate_valid(data, i); i = IterableMappingNcc.iterate_next(data, i)) {
            var (key, value) = IterableMappingNcc.iterate_get(data, i);
            if (value.participants[0].addr == adr) channels.push(key);
            else if (value.participants[1].addr == adr) channels.push(key);
        }
        if (channels.length == 0) throw; //maybe find other way to show that no such channel exists
    }


    /// @notice key(address, address) to create a key of the two addressed.
    /// @dev Get a hashed key of two addresses.
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return key (bytes32) sha3 hash of the two keys.
    function key(address adrA, address adrB) constant returns (bytes32 key){
        if (adrA == adrB) throw;
        if (adrA > adrB) return sha3(adrA, adrB);
        else return sha3(adrB, adrA);
    }


    /// @notice add(NettingContract) to add a channel to the collection of NettingContracts.
    /// @dev Add a NettingContract to nettingContracts if it doesn't already exist.
    /// @param channel (NettingContract) the payment channel.
    function add(bytes32 key, NettingContract channel) {
        if (IterableMappingNcc.contains(data, key)) throw;
        IterableMappingNcc.insert(data, key, channel);
    }


    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return channel (NettingContract) the value of the NettingContract of the two parties.
    function get(address adrA, address adrB) returns (NettingContract channel){
        ky = key(adrA, adrB);
        if (!IterableMappingNcc.contains(data, ky)) throw; //handle if no such channel exists
        uint index = IterableMappingNcc.atIndex(data, ky);
        var (k, v) = IterableMappingNcc.iterate_get(data, index - 1);
        channel = v;
    }


    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return channel (NettingContract) the NettingContract of the two parties.
    function newChannel(address adrA, address adrB) returns (NettingContract c){
        k = key(adrA, adrB);
        c = NettingContract(assetAddress);
        add(k, c);
        return c;
        ChannelNew(k, c); //Triggers event
    }


    // empty function to handle wrong calls
    function () { throw; }
}
