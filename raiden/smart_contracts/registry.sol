// For iterable mapping
import "cmcItSet.sol";

contract Registry {
    IterableMappingCMC.itmap data; // Might be the data structure to use


    /// @notice addAsset(address) to add a new ChannelManagerContract to channelManagerContracts
    /// with the assetAddress as key.
    /// @dev Add a new ChannelManagerContract to channelManagerContracts if assetAddress 
    /// does not already exist.
    /// @param assetAddress (address) the address of the asset
    /// @return nothing, but updates the collection of ChannelManagerContracts.
    function addAsset(address assetAddress) {
        // only allow unique addresses
        if (IterableMappingCMC.contains(data, assetAddress)) throw;
        ChannelManagerContract c = ChannelManagerContract(assetAddress);
        IterableMappingCMC.insert(data, assetAddress, c);
    }


    /// @notice channelManagerByAsset(address) to get the ChannelManagerContract 
    /// of the given assetAddress.
    /// @dev Get the ChannelManagerContract of a given assetAddress.
    /// @param assetAddress (address) the asset address.
    /// @return cmc (ChannelManagerContract) the contract belonging to an assetAddress.
    function channelManagerByAsset(address assetAddress) returns (ChannelManagerContract cmc) {
        // if assetAddress does not exist, throw
        if (IterableMappingCMC.contains(data, assetAddress) == false) throw;
        uint index = IterableMappingCMC.atIndex(data, assetAddress);
        var(key, value) = IterableMappingCMC.iterate_get(data, index - 1);
        cmc = value;
    }


    /// @notice assetAddresses() to get all assetAddresses in the collection.
    /// @dev Get all assetAddresses in the collection.
    /// @return assetAddress (address[]) an array of all assetAddresses
    function assetAddresses() returns (address[] assetAddresses) {
        assetAddresses = new address[](data.size)
        for (var i = IterableMappingCMC.iterate_start(data); IterableMappingCMC.iterate_valid(data, i); i = IterableMappingCMC.iterate_next(data, i)) {
            var (key, value) = IterableMappingCMC.iterate_get(data, i);
            assetAddresses[i] = key;
        }
    }


    // ONLY FOR TESTING PURPOSES
    /*
    address constant TEST_ADDRESS1 = 0x123345;
    address constant ASSET_ADDRESS = 0xC0FFEE;
    address constant TEST_ADDRESS2 = 0xDEADBEEF;
    address constant TEST_ADDRESS3 = 0xABCDEF;
    function testGetAllAddresses() returns (bool success, address[] a) {
        ChannelManagerContract cmc = new ChannelManagerContract(ASSET_ADDRESS);
        addAsset(TEST_ADDRESS1);
        addAsset(TEST_ADDRESS2);
        addAsset(TEST_ADDRESS3);
        success = data.size == 3;
        a = assetAddresses();
    }
    */

    // empty function to handle wrong calls
    function () { throw; }
}
