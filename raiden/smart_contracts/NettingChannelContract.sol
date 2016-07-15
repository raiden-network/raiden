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
    function closingAddress() constant returns (address) {
        return data.closingAddress;
    }

    function () { throw; }
}
