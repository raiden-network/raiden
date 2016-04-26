/*
    Wrapper and tests for the data structure of ChannelManager contracts
    To run tests, use Solidity online compiler and execute the test funtions
    One should see some 1's indicating success.
*/


/// @dev Models a uint -> uint mapping where it is possible to iterate over all keys.
library IterableMappingCMC {
    // Might have to define the NettingContract type here for insertion
    struct itmap {
        mapping(address => IndexValue) data;
        KeyFlag[] keys;
        uint size;
    }
    struct IndexValue { uint keyIndex; ChannelManagerContract value; }
    struct KeyFlag { address key; bool deleted; }


    function insert(itmap storage self, address key, ChannelManagerContract value) returns (bool replaced) {
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


    function remove(itmap storage self, address key) returns (bool success){
        uint keyIndex = self.data[key].keyIndex;
        if (keyIndex == 0) return false;
        delete self.data[key];
        self.keys[keyIndex - 1].deleted = true;
        self.size --;
    }


    function contains(itmap storage self, address key) returns (bool) {
        return self.data[key].keyIndex > 0;
    }


    function atIndex(itmap storage self, address key) returns (uint index) {
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


    function iterate_get(itmap storage self, uint keyIndex) returns (address key, ChannelManagerContract value){
        key = self.keys[keyIndex].key;
        value = self.data[key].value;
    }
}


// How to use it:
contract Wrapper
{
    // Just a struct holding our data.
    IterableMapping.itmap data;
    // Insert something
    function insert(address k, ChannelManagerContract v) returns (uint size)
    {
        // Actually calls itmap_impl.insert, auto-supplying the first parameter for us.
        IterableMapping.insert(data, k, v);
        // We can still access members of the struct - but we should take care not to mess with them.
        return data.size;
    }

    function contains(address k) returns (bool c) {
        c = IterableMapping.contains(data, k);
    }
    
    function lengthOf() returns (uint l) {
        l = data.keys.length - 1;
    }

    function get(address k) returns (address key, ChannelManagerContract value) {
        uint index = IterableMapping.atIndex(data, k);
        (key, value) = IterableMapping.iterate_get(data, index -1);
    }

    function remove(address k) returns (bool success) {
        success = IterableMapping.remove(data, k);
    }

    function getIndex(address k) returns (uint i) {
        i = IterableMapping.atIndex(data, k);
    }

    function getAllKeys() returns (address[] addresses) {
        for (var i = IterableMapping.iterate_start(data); IterableMapping.iterate_valid(data, i); i = IterableMapping.iterate_next(data, i)) {
            var(key, value) = IterableMapping.iterate_get(data, i);
            addresses[i] = key;
        }
    }

}

contract cmcItSetTest {

    address constant TEST_ADDRESS1 = 0x123345;
    address constant ASSET_ADDRESS = 0xC0FFEE;
    address constant TEST_ADDRESS3 = 0xABCDEF;


    function testInsert() returns (bool has, bool isIn){
        ChannelManagerContract cmc = new ChannelManagerContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_ADDRESS1, cmc);
        has = wrp.contains(TEST_ADDRESS1);
        var(a, c) = wrp.get(TEST_ADDRESS1);
        isIn = c.assetAddress() == ASSET_ADDRESS && a == TEST_ADDRESS1; 
        return;
    }

    function testRemove() returns (bool removed, bool isIn, bool exist) {
        ChannelManagerContract cmc = new ChannelManagerContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_ADDRESS1, cmc);
        wrp.lengthOf() == 1;
        exist = wrp.contains(TEST_ADDRESS1);
        wrp.remove(TEST_ADDRESS1);
        removed = wrp.lengthOf() == 0;
        isIn = false == wrp.contains(TEST_ADDRESS1);
        return;
    }
    
    function testIndex() returns (bool at) {
        ChannelManagerContract cmc = new ChannelManagerContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_ADDRESS1, cmc);
        at = 1 == wrp.getIndex(TEST_ADDRESS1);
        return;
    }
    
    // THIS TEST CANNOT WORK SINCE DYNAMIC ARRAYS CANNOT BE PASSED
    // AROUND BETWEEN CONTRACTS.
    function testGetAllAddresses() returns (bool success) {
        ChannelManagerContract cmc = new ChannelManagerContract(ASSET_ADDRESS);
        Wrapper wrp = new Wrapper();
        wrp.insert(TEST_ADDRESS1, cmc);
        wrp.insert(TEST_ADDRESS3, cmc);
        //address[] a = wrp.getAllKeys(); // not working
        //success = a.length == 2;
        return;
    }
}

contract ChannelManagerContract {
    address public assetAddress;
    
    function ChannelManagerContract(address testAddress) {
        assetAddress = testAddress;
    }
}
