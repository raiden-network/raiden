// For iterable mapping
import "github.com/ethereum/dapp-bin/library/iterable_mapping.sol";

contract BlockChain {
    /*IterableMapping.itmap channelManagerContracts; // Might be the data structure to use*/

    address assetAddres;
    mapping(address => ChannelManagerContract) public channelManagerContracts;


    /// @notice addAsset(address) to add a new ChannelManagerContract to channelManagerContracts
    /// with the assetAddress as key.
    /// @dev Add a new ChannelManagerContract to channelManagerContracts if assetAddress 
    /// does not already exist.
    /// @param assetAddress (address) the address of the asset
    /// @return nothing, but updates the collection of ChannelManagerContracts.
    function addAsset(address assetAddress) {
        // Check if the assetAddress already exists as key in the collection. Throw if it does.
        // Create a new ChannelManagerContract and add it to the collection.

        /*channelManagerContracts[assetAddress] = ChannelManagerContract(assetAddress);*/
    }


    /// @notice channelManagerByAsset(address) to get the ChannelManagerContract 
    /// of the given assetAddress.
    /// @dev Get the ChannelManagerContract of a given assetAddress.
    /// @param assetAddress (address) the asset address.
    /// @return cmc (ChannelManagerContract) the contract belonging to an assetAddress.
    function channelManagerByAsset(address assetAddress) constant returns (ChannelManagerContract cmc) {
        return channelManagerContracts[assetAddress];
    }


    /// @notice assetAddresses() to get all assetAddresses in the collection.
    /// @dev Get all assetAddresses in the collection.
    /// @return assetAddress (address[]) an array of all assetAddresses
    function assetAddresses() returns (address[] assetAddress) {
        // get all keys(assetAddress) in the collection and return them in an array
    }
}
