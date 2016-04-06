// For iterable mapping
import "cmcItSet.sol";

contract BlockChain {
    IterableMappingCMC.itmap data; // Might be the data structure to use

    address assetAddres;

    /// @notice addAsset(address) to add a new ChannelManagerContract to channelManagerContracts
    /// with the assetAddress as key.
    /// @dev Add a new ChannelManagerContract to channelManagerContracts if assetAddress 
    /// does not already exist.
    /// @param assetAddress (address) the address of the asset
    /// @return nothing, but updates the collection of ChannelManagerContracts.
    function addAsset(address assetAddress) {
        // Check if the assetAddress already exists as key in the collection. Throw if it does.
        // Create a new ChannelManagerContract and add it to the collection.
        if (IterableMappingCMC.contains(data, assetAddress)) throw;
        c = ChannelManagerContract(assetAddress);
        IterableMappingCMC.insert(data, assetAddress, c);
    }


    /// @notice channelManagerByAsset(address) to get the ChannelManagerContract 
    /// of the given assetAddress.
    /// @dev Get the ChannelManagerContract of a given assetAddress.
    /// @param assetAddress (address) the asset address.
    /// @return cmc (ChannelManagerContract) the contract belonging to an assetAddress.
    function channelManagerByAsset(address assetAddress) returns (ChannelManagerContract cmc) {
        uint index = IterableMappingCMC.atIndex(data, assetAddress);
        var(key, value) = IterableMappingCMC.iterate_get(data, index - 1);
        cmc = value;
    }


    /// @notice assetAddresses() to get all assetAddresses in the collection.
    /// @dev Get all assetAddresses in the collection.
    /// @return assetAddress (address[]) an array of all assetAddresses
    function assetAddresses() returns (address[] assetAddresses) {
        // get all keys(assetAddress) in the collection and return them in an array
        address[] addresses;
        for (var i = IterableMappingCMC.iterate_start(data); IterableMappingCMC.iterate_valid(data, i); i = IterableMappingCMC.iterate_next(data, i)) {
            var (key, value) = IterableMappingCMC.iterate_get(data, i);
            addresses.push(key);;
        }
        assetAddresses = addresses;
    }


    // empty function to handle wrong calls
    function () { throw; }
}
