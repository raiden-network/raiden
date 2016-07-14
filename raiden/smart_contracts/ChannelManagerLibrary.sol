import "Token.sol";
import "NettingChannelLibrary.sol";

contract NettingChannelContract {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    function NettingChannelContract(address assetAddress, address participant1, address participant2, uint timeout) {
        if (timeout < 30) {
            timeout = 30;
        }

        data.participants[0].nodeAddress = participant1;
        data.participants[1].nodeAddress = participant2;

        data.token = Token(assetAddress);
        data.settleTimeout = timeout;
    }

    function deposit(uint256 amount) {
        data.deposit(msg.sender, this, amount);
    }
    function partner(address one_address) constant returns (address) {
        return data.partner(one_address);
    }
    function addressAndBalance() constant returns (address participant1, uint balance1, address participant2, uint balance2) {
        return data.addressAndBalance();
    }
    function closeSingleTransfer(bytes signed_transfer) {
        data.closeSingleTransfer(msg.sender, signed_transfer);
    }
    function close(bytes firstEncoded, bytes secondEncoded) {
        data.close(msg.sender, firstEncoded, secondEncoded);
    }
    function updateTransfer(bytes signed_transfer) {
        data.updateTransfer(msg.sender, signed_transfer);
    }
    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) {
        data.unlock(msg.sender, lockedEncoded, merkleProof, secret);
    }
    function settle() {
        data.settle(msg.sender);
    }
    function settleTimeout() constant returns (uint) {
        return data.settleTimeout;
    }
    function assetAddress() constant returns (address) {
        return data.token;
    }
    function opened() constant returns (uint) {
        return data.opened;
    }
    function closed() constant returns (uint) {
        return data.closed;
    }
    function settled() constant returns (uint) {
        return data.settled;
    }

    function () { throw; }
}

library ChannelManagerLibrary {
    // TODO: experiment with a sorted data structure
    struct Data {
        mapping(address => address[]) nodeChannels;
        address[] all_channels;
    }

    event ChannelNew(
        address nettingChannel,
        address participant1,
        address participant2,
        uint settleTimeout
    );

    function getAllChannels(Data storage self) returns (address[] channels) {
        channels = self.all_channels;
    }

    /// @notice nettingContractsByAddress(address) to get nettingContracts that 
    /// the address participates in.
    /// @dev Get channels where the given address participates.
    /// @return Array of the channel's addresses that nodeAddress participates.
    function getChannelsForNode(Data storage self, address nodeAddress) constant returns (address[]) {
        return self.nodeChannels[nodeAddress];
    }

    /// @notice get(address, address) to get the unique channel of two parties.
    /// @dev Get the channel of two parties
    /// @return channel (NettingChannelContract) the value of the NettingChannelContract of the two parties.
    function getChannelWith(Data storage self, address partner) constant returns (address) {
        uint i;
        address[] our_channels = self.nodeChannels[msg.sender];
        address channel;

        for (i=0; i < our_channels.length; ++i) {
            channel = our_channels[i];

            if (NettingChannelContract(channel).partner(msg.sender) == partner) {
                return channel;
            }
        }
    }

    /// @notice newChannel(address, address) to create a new payment channel between two parties
    /// @dev Create a new channel between two parties
    /// @return NettingChannelContract's address.
    function newChannel(Data storage self, address assetToken, address partner, uint settleTimeout) returns (address) {
        address channelAddress;

        channelAddress = new NettingChannelContract(
            assetToken,
            msg.sender,
            partner,
            settleTimeout
        );
        ChannelNew(
            channelAddress,
            msg.sender,
            partner,
            settleTimeout
        );

        self.nodeChannels[msg.sender].push(channelAddress);
        self.nodeChannels[partner].push(channelAddress);
        self.all_channels.push(channelAddress);

    }
}
