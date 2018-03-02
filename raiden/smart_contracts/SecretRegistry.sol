pragma solidity ^0.4.17;

contract SecretRegistry {

    /*
     *  Data structures
     */

    string constant public contract_version = "0.3._";

    // Token address => TokenNetwork address
    mapping(bytes32 => uint64) public secret_to_block;

    /*
     *  Events
     */

    event SecretRevealed(bytes32 secret);

    function registerSecret(bytes32 secret) public {
        require(secret_to_block[secret] == 0);
        secret_to_block[secret] = uint64(block.number);
        SecretRevealed(secret);
    }

    function getSecretBlockHeight(bytes32 secret) public constant returns (uint64) {
        return secret_to_block[secret];
    }
}
