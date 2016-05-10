# -*- coding: utf8 -*-
import pytest


from ethereum import utils
from ethereum import tester
from ethereum.utils import sha3, privtoaddr
from ethereum.tester import TransactionFailed

library_code = '''
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
        participants[0].deposit = 10;
        participants[1].deposit = 10;
    }
}

/// Iteratable data structure of the type [bytes32 k, NettingContract v]
library IterableMappingNcc
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
'''

cmc_code = '''
library IterableMappingNcc
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

contract NettingContract {
    address public assetAddress;
    address public TEST_ADDRESS1 = 0x123456;
    address public TEST_ADDRESS2 = 0x654321;
    
    struct Participant
    {
        address addr;
        uint deposit;
    }

    Participant[2] public participants; // Might make more sense to use an array like this for participants */
                                 /*// since it only holds two.*/

    function NettingContract(address assetAdr) {
        assetAddress = assetAdr;
        participants[0].addr = TEST_ADDRESS1;
        participants[1].addr = TEST_ADDRESS2;
        participants[0].deposit = 10;
        participants[1].deposit = 10;
    }
}

contract ChannelManagerContract {

    IterableMappingNcc.itmap data;

    address assetAddress;

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
        channels = new NettingContract[](data.keys.length);
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
    function newChannel(address partner) returns (NettingContract c){
        bytes32 k = key(msg.sender, partner);
        c = new NettingContract(getAssetAddress());
        add(k, c);
        ChannelNew(partner); //Triggers event
    }

    function getAssetAddress() returns (address) {
        return assetAddress;
    }


    // empty function to handle wrong calls
    function () { throw; }
}
'''


def test_cmc():
    s = tester.state()
    assert s.block.number < 1150000
    s.block.number = 1158001
    assert s.block.number > 1150000
    lib_c = s.abi_contract(library_code, language="solidity")
    c = s.abi_contract(cmc_code, language="solidity", libraries={'IterableMappingNcc': lib_c.address.encode('hex')})

    # a0 = c.ChannelManagerContract(sha3('asset')[:20].encode('hex'))
    # assert a0.assetAddress == sha3('asset')[:20].encode('hex')

    print(s.__dict__)

    # test key()
    vs = sorted((sha3('address1')[:20], sha3('address2')[:20]))
    k0 = c.key(sha3('address1')[:20], sha3('address2')[:20])
    assert k0 == sha3(vs[0] + vs[1])
    k1 = c.key(sha3('address2')[:20], sha3('address1')[:20])
    assert k1 == sha3(vs[0] + vs[1])
    with pytest.raises(TransactionFailed):
        c.key(sha3('address1')[:20], sha3('address1')[:20])

    # test newChannel()
    assert c.getAssetAddress() == sha3('asset')[:20].encode('hex')
    nc1 = c.newChannel(sha3('address1')[:20])
    nc2 = c.newChannel(sha3('address3')[:20])
    with pytest.raises(TransactionFailed):
        c.newChannel(sha3('address1')[:20], sha3('address2')[:20])
    with pytest.raises(TransactionFailed):
        c.newChannel(sha3('address2')[:20], sha3('address2')[:20])

    # TODO test event()

    # TODO set participants addresses directly in newChannel()?
    assert nc1.participants[0].addr == sha3(s.a0)[:20]
    assert nc1.participants[1].addr == sha3('address1')[:20]

    # test get()
    chn1 = c.get(s.a0, sha3('address1')[:20])
    assert chn1.assetAddress == sha3('asset')[:20].encode('hex')
