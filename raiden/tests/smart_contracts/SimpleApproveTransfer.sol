contract SimpleApproveTransfer {
    address asset; 

    function SimpleApproveTransfer(address assetAddress) {
        asset = assetAddress;
    }

    function transfer(address to, uint256 amount) returns (bool) {
        return asset.call(
            bytes4(bytes32(sha3("transferFrom(address,address,uint256)"))),
            msg.sender,
            to,
            amount
        );
    }
}
