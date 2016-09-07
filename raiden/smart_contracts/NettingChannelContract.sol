import "NettingChannelLibrary.sol";

contract NettingChannelContract {
    using NettingChannelLibrary for NettingChannelLibrary.Data;
    NettingChannelLibrary.Data public data;

    event ChannelNewBalance(address assetAddress, address participant, uint balance, uint blockNumber);
    event ChannelClosed(address closingAddress, uint blockNumber);
    event ChannelSettled(uint blockNumber);
    event ChannelSecretRevealed(bytes32 secret);

    modifier settleTimeoutNotTooLow(uint t) {
        if (t < 6) throw;
        _
    }

    function NettingChannelContract(
        address assetAddress,
        address participant1,
        address participant2,
        uint timeout)
        settleTimeoutNotTooLow(timeout)
    {
        if (participant1 == participant2) {
            throw;
        }

        data.participants[0].nodeAddress = participant1;
        data.participants[1].nodeAddress = participant2;

        data.token = Token(assetAddress);
        data.settleTimeout = timeout;
    }

    function deposit(uint256 amount) returns (bool) {
        bool success;
        uint256 balance;

        (success, balance) = data.deposit(msg.sender, this, amount);

        if (success == true) {
            ChannelNewBalance(data.token, msg.sender, balance, data.opened);
        }

        return success;
    }

    function partner(address one_address) constant returns (address) {
        return data.partner(one_address);
    }

    function addressAndBalance() constant returns (address participant1, uint balance1, address participant2, uint balance2) {
        return data.addressAndBalance();
    }

    function closeSingleTransfer(bytes signed_transfer) {
        data.closeSingleTransfer(msg.sender, signed_transfer);
        ChannelClosed(msg.sender, data.closed);
    }

    function close(bytes firstEncoded, bytes secondEncoded) {
        data.close(msg.sender, firstEncoded, secondEncoded);
        ChannelClosed(msg.sender, data.closed);
    }

    function updateTransfer(bytes signed_transfer) {
        data.updateTransfer(msg.sender, signed_transfer);
    }

    function unlock(bytes lockedEncoded, bytes merkleProof, bytes32 secret) {
        data.unlock(msg.sender, lockedEncoded, merkleProof, secret);
        ChannelSecretRevealed(secret);
    }

    function settle() {
        data.settle(msg.sender);
        ChannelSettled(data.settled);
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
