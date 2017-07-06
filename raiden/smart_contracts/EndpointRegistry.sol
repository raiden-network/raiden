/*
 * This contract is a registry which maps the Ethereum Address to their
 *  endpoint i.e sockets.
 * The Ethereum address registers his address in this registry.
*/

pragma solidity ^0.4.0;

contract EndpointRegistry{
    event AddressRegistered(address indexed eth_address, string socket);

    // Mapping of Ethereum Addresses => SocketEndpoints
    mapping (address => string) address_to_socket;
    // Mapping of SocketEndpoints => Ethereum Addresses
    mapping (string => address) socket_to_address;
    // list of all the Registered Addresses , still not used.
    address[] eth_addresses;

    modifier noEmptyString(string str)
    {
        if (equals(str, "") == true) {
            throw;
        }
        _;
    }

    /*
     * @notice Registers the Ethereum Address to the Endpoint socket.
     * @dev Registers the Ethereum Address to the Endpoint socket.
     * @param string of socket in this format "127.0.0.1:40001"
     */
    function registerEndpoint(string socket) noEmptyString(socket)
    {
        string old_socket = address_to_socket[msg.sender];

        // Compare if the new socket matches the old one, if it does just return
        if (equals(old_socket, socket)) {
            return;
        }

        // Put the ethereum address 0 in front of the old_socket,old_socket:0x0
        socket_to_address[old_socket] = address(0);
        address_to_socket[msg.sender] = socket;
        socket_to_address[socket] = msg.sender;
        AddressRegistered(msg.sender, socket);
    }

    /*
     * @notice Finds the socket if given an Ethereum Address
     * @dev Finds the socket if given an Ethereum Address
     * @param An eth_address which is a 20 byte Ethereum Address
     * @return A socket which the current Ethereum Address is using.
     */
    function findEndpointByAddress(address eth_address) constant returns (string socket)
    {
        return address_to_socket[eth_address];
    }

    /*
     * @notice Finds Ethreum Address if given an existing socket address
     * @dev Finds Ethreum Address if given an existing socket address
     * @param string of socket in this format "127.0.0.1:40001"
     * @return An ethereum address
     */
    function findAddressByEndpoint(string socket) constant returns (address eth_address)
    {
        return socket_to_address[socket];
    }

    function equals(string a, string b) internal constant returns (bool result)
    {
        if (sha3(a) == sha3(b)) {
            return true;
        }

        return false;
    }
}
