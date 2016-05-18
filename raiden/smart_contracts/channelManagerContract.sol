library IterableMappingNcc {
    // Might have to define the NettingContract type here for insertion
    struct itmap {
        mapping(bytes32 => IndexValue) data;
        KeyFlag[] keys;
        uint size;
    }
    struct IndexValue { uint keyIndex; NettingContract value; }
    struct KeyFlag { bytes32 key; bool deleted; }


    function insert(itmap storage self, bytes32 key, NettingContract value) returns (bool replaced) {
        uint keyIndex = self.data[key].keyIndex;
        self.data[key].value = value;
        if (keyIndex > 0)
            return true;
        else {
            keyIndex = self.keys.length++;
            self.data[key].keyIndex = keyIndex + 1;
            self.keys[keyIndex].key = key;
            self.size++;
            return false;
        }
    }


    function remove(itmap storage self, bytes32 key) returns (bool success){
        uint keyIndex = self.data[key].keyIndex;
        if (keyIndex == 0)
          return false;
        delete self.data[key];
        self.keys[keyIndex - 1].deleted = true;
        self.size --;
    }


    function contains(itmap storage self, bytes32 key) returns (bool) {
        return self.data[key].keyIndex > 0;
    }


    function atIndex(itmap storage self, bytes32 key) returns (uint index) {
        return self.data[key].keyIndex;
    }


    function iterate_start(itmap storage self) returns (uint keyIndex){
        return iterate_next(self, uint(-1));
    }


    function iterate_valid(itmap storage self, uint keyIndex) returns (bool){
        return keyIndex < self.keys.length;
    }


    function iterate_next(itmap storage self, uint keyIndex) returns (uint r_keyIndex){
        keyIndex++;
        while (keyIndex < self.keys.length && self.keys[keyIndex].deleted)
            keyIndex++;
        return keyIndex;
    }


    function iterate_get(itmap storage self, uint keyIndex) returns (bytes32 key, NettingContract value){
        key = self.keys[keyIndex].key;
        value = self.data[key].value;
    }
}

contract NettingContract {
    address public assetAddress;
    
    struct Participant
    {
        address addr;
        uint deposit;
    }

    Participant[2] public participants;

    function NettingContract(address assetAdr, address participant1, address participant2) {
        assetAddress = assetAdr;
        participants[0].addr = participant1;
        participants[1].addr = participant2;
        participants[0].deposit = 10;
        participants[1].deposit = 10;
    }
}

contract ChannelManagerContract {

    IterableMappingNcc.itmap data;

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
        assetAddress = 0x0bd4060688a1800ae986e4840aebc924bb40b5bf;
    }


    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @param adr (address) the address
    /// @return channels (NettingContracts[]) all channels that a given address participates in.
    function nettingContractsByAddress(address adr) returns (NettingContract[] channels){
        channels = new NettingContract[](numberOfItems(adr));
        uint idx = 0;
        for (var i = IterableMappingNcc.iterate_start(data); IterableMappingNcc.iterate_valid(data, i); i = IterableMappingNcc.iterate_next(data, i)) {
            var (key, value) = IterableMappingNcc.iterate_get(data, i);
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

    function numberOfItems(address adr) returns (uint items) {
        items = 0;
        for (var i = IterableMappingNcc.iterate_start(data); IterableMappingNcc.iterate_valid(data, i); i = IterableMappingNcc.iterate_next(data, i)) {
            var (key, value) = IterableMappingNcc.iterate_get(data, i);
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
    

    /// @notice key(address, address) to create a key of the two addressed.
    /// @dev Get a hashed key of two addresses.
    /// @param adrA (address) address of one party.
    /// @param adrB (address) address of other party.
    /// @return key (bytes32) sha3 hash of the two keys.
    function key(address adrA, address adrB) returns (bytes32 key){
        if (adrA == adrB) throw;
        if (adrA < adrB) return sha3(adrA, adrB);
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
        bytes32 ky = key(adrA, adrB);
        if (IterableMappingNcc.contains(data, ky) == false) throw; //handle if no such channel exists
        uint index = IterableMappingNcc.atIndex(data, ky);
        var (k, v) = IterableMappingNcc.iterate_get(data, index - 1); // -1 ?
        channel = v;
    }


    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @param partner (address) address of one partner
    /// @return channel (NettingContract) the NettingContract of the two parties.
    function newChannel(address partner) returns (NettingContract c, address sender){
        bytes32 k = key(msg.sender, partner);
        c = new NettingContract(assetAddress, msg.sender, partner);
        add(k, c);
        sender = msg.sender; // Only for testing purpose, should not be added to live net
        ChannelNew(partner); //Triggers event
    }

    // empty function to handle wrong calls
    function () { throw; }
}
