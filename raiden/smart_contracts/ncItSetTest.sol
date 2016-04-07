/*
    Work in process
    Still a couple of issues
*/


/// Iteratable data structure of the type [bytes32 k, NettingContract v]
library IterableMapping
{
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
contract Wrapper
{
    // Just a struct holding our data.
    IterableMapping.itmap data;
    // Insert something
    function insert(bytes32 k, NettingContract v) returns (uint size)
    {
        // Actually calls itmap_impl.insert, auto-supplying the first parameter for us.
        IterableMapping.insert(data, k, v);
        // We can still access members of the struct - but we should take care not to mess with them.
        return data.size;
    }

    function contains(bytes32 k) returns (bool c) {
        c = IterableMapping.contains(data, k);
    }
    
    function lengthOf() returns (uint l) {
        l = data.keys.length;
    }

    function get(bytes32 k) returns (bytes32 key, NettingContract value) {
        uint index = IterableMapping.atIndex(data, k);
        (key, value) = IterableMapping.iterate_get(data, index -1);
    }

    function remove(bytes32 k) returns (bool success) {
        success = IterableMapping.remove(data, k);
    }

    function getIndex(bytes32 k) returns (uint i) {
        i = IterableMapping.atIndex(data, k);
    }

    function getAllKeys() returns (address[] addresses) {
        address[] arr;
        for (var i = IterableMapping.iterate_start(data); IterableMapping.iterate_valid(data, i); i = IterableMapping.iterate_next(data, i)) {
            var(key, value) = IterableMapping.iterate_get(data, i);
            arr.push(address(key));
        }
        addresses = arr; // this seems to not be working. What is the correct way to do this?
    }

    /// This is not a helper method for this data structure. Use for ncc data structure
    /*function getValues(address v) returns (address[] values) {*/
        /*for (var i = IterableMapping.iterate_start(data); IterableMapping.iterate_valid(data, i); i = IterableMapping.iterate_next(data, i)) {*/
            /*var (key, value) = IterableMapping.iterate_get(data, i);*/
            /*// should we return just the keys to the contracts or entire contracts?*/
            /*// The way this check is executed depends on the datastructure we decide*/
            /*// to use for participants.*/
            /*if (value.participants[0].addr == adr) channels.push(key);*/
            /*else if (value.participants[1].addr == adr) channels.push(key);*/
        /*}*/
        /*if (channels.length == 0) throw; //maybe find other way to show that no such channel exists*/
    /*}*/
}

contract NettingContractTest {
    bytes32 constant TEST_KEY2 = 0xBEEEEF;
    bytes32 constant TEST_KEY3 = 0x654321;
    address constant TEST_ADDRESS1 = 0x123456;
    address constant TEST_ADDRESS2 = 0x654321;
    address constant ASSET_ADDRESS = 0xDEADBEEF;
    bytes32 constant TEST_KEY1 = sha3(TEST_ADDRESS1, TEST_ADDRESS2);


    function testInsert() returns (bool isIn, bool has, bool hasPar) {
        NettingContract nc = new NettingContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_KEY1, nc);
        isIn = wrp.contains(TEST_KEY1);
        var(k, c) = wrp.get(TEST_KEY1);
        has = k == TEST_KEY1 && c.assetAddress() == ASSET_ADDRESS;
        hasPar = c.participants[0].addr == TEST_ADDRESS1;
    }
    
    function testRemove() returns (bool removed, bool isIn, bool exist) {
        NettingContract nc = new NettingContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_KEY1, nc);
        wrp.lengthOf() == 2; //why is lenght 2?
        exist = wrp.contains(TEST_KEY1);
        wrp.remove(TEST_KEY1);
        removed = wrp.lengthOf() == 1;
        isIn = false == wrp.contains(TEST_KEY1);
        return;
    }

}

// Just for the sake of interface
contract NettingContract {
    uint lockedTime;
    address public assetAddress;
    uint public opened;
    uint public closed;
    uint public settled;
    address public TEST_ADDRESS1 = 0x123456;
    address public TEST_ADDRESS2 = 0x654321;
    
    struct Transfer {} // TODO
    struct Unlocked {} // TODO
    struct Participant
    {
        address addr;
        uint deposit;
        //Transfer[] lastSentTransfers;
        //Unlocked unlocked;
    }
    //mapping(address => Participant) public participants;

    Participant[2] public participants; // Might make more sense to use an array like this for participants */
                                 /*// since it only holds two.*/

    event ChannelOpened(address assetAdr); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO

    function NettingContract(address assetAdr) {
        opened = 0;
        closed = 0;
        settled = 0;
        assetAddress = assetAdr;
        participants[0].addr = TEST_ADDRESS1;
        participants[1].addr = TEST_ADDRESS2;
    }
    
    function testPar() returns (bool test) {
        test = participants[0].addr == TEST_ADDRESS1;
    }
}
