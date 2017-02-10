contract SimpleApproveTransfer {
    address token; 

    function SimpleApproveTransfer(address tokenAddress) {
        token = tokenAddress;
    }

    function transfer(address to, uint256 amount) returns (bool) {
        return token.call(
            bytes4(bytes32(sha3("transferFrom(address,address,uint256)"))),
            msg.sender,
            to,
            amount
        );
    }
}
