contract ChannelManagerContract {
    address assetAddress;
    NettingContract[] nettingContracts; // need to change data structure, name persistst

    // Events
    // Event that triggers when a new channel is created
    // Gives the created channel
    event ChannelNew(NettingContract channel);

    // Initialize the Contract
    function ChannelManagerContract(address assetAdr) {
        assetAddress = assetAdr;
    }


    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param adr (address) the address
    /// @return channels (NettingContracts[]) all channels that a given address participates in.
    function nettingContractsByAddress(address adr) returns (NettingContract[] channels){
        // Need to have a datastructure that allows for something like this:
        // return [c for c in self.nettingcontracts.values() if address in c.participants]
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
    function add(NettingContract channel) {
        // hash the addresses of the two participants
        // if key exists in nettingContracts then throw;
        // otherwise add channel to nettingContracts with key as key
    }


    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return channel (NettingContract) the NettingContract of the two parties.
    function get(address adrA, address adrB) returns (NettingContract channel){
        k = key(adrA, adrB);
        return nettingContracts[k];
        //handle if no such channel exists
    }


    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return channel (NettingContract) the NettingContract of the two parties.
    function newChannel(address adrA, address adrB) returns (NettingContract c){
        c = NettingContract(assetAddress, adrA, adrB);
        add(c);
        return c;
        ChannelNew(c);
    }
}
