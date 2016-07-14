/*
This contract is a registry which maps the Ethereum Address to their endpoint i.e sockets.
The Ethereum address registers his address in this registry.
*/

<<<<<<< HEAD
contract EndpointRegistry{

//Events

	event AddressRegistered(address indexed eth_address,string indexed socket);
    event AddressUpdated(address indexed eth_address,string indexed old_socket,string indexed newSocket);

//Storage Variables

	//Mapping of Ethereum Addresses => SocketEndpoints
	mapping (address => string) addressToSocket;
	//Mapping of SocketEndpoints => Ethereum Addresses
	mapping (string => address) socketToAddress;
	//list of all the Registered Addresses , still not used.
	address[] eth_addresses;

//modifiers

    modifier nodoubleregister
    {
    	if(sha3(addressToSocket[msg.sender])!= sha3("")) throw;
    	_	
    }

    modifier endpointExists
    {
    	if(sha3(addressToSocket[msg.sender]) == sha3("")) throw;
        _
    }

    modifier noEmptyString(string str)
    {
        if(equals(str,"") == true) throw;
        _
    }

//Functions 

    /* 
    @notice Registers the Ethereum Address to the Endpoint socket.
    @dev Registers the Ethereum Address to the Endpoint socket.
    @param string of socket in this format "127.0.0.1:40001" 
    */
    function registerEndpoint(string socket) nodoubleregister 
    {
    	addressToSocket[msg.sender] = socket;
    	socketToAddress[socket] = msg.sender;
        AddressRegistered(msg.sender,socket);
    }

    /* 
    @notice Updates an existing mapping to a new socket
    @dev Updates an existing mapping to a new socket
    @param string of socket in this format "127.0.0.1:40001"  
    */
    function updateEndpoint(string socket) endpointExists noEmptyString(socket)
    {
    	string old_socket = addressToSocket[msg.sender];
    	socketToAddress[old_socket]	= address(0);
    	addressToSocket[msg.sender] = socket;
    	socketToAddress[socket] = msg.sender;
        AddressUpdated(msg.sender,old_socket,socket);
    }

    /* 
    @notice Finds the socket if given an Ethereum Address
    @dev Finds the socket if given an Ethereum Address
    @param An eth_address which is a 20 byte Ethereum Address
    @return A socket which the current Ethereum Address is using.  
    */
    function findEndpointByAddress(address eth_address) constant returns (string socket)
    {
        return addressToSocket[eth_address];
    }

    /* 
    @notice Finds Ethreum Address if given an existing socket address 
    @dev Finds Ethreum Address if given an existing socket address
    @param string of socket in this format "127.0.0.1:40001"  
    @return An ethereum address
    */
    function findAddressByEndpoint(string socket) constant returns (address eth_address)
    {
    	return socketToAddress[socket];
    }

    function equals(string a,string b) internal constant returns (bool result)
    {
    if(sha3(a) == sha3(b)) return true;
    else return false;
    }

<<<<<<< HEAD
}
=======
}
>>>>>>> Added the EndpointRegistry Contract and test_endpointregistry.py for issue 80
