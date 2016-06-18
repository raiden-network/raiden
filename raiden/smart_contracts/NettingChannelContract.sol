import "StandardToken.sol";

contract NettingChannelContract {
    uint public lockedTime;
    address public assetAddress;
    uint public opened;
    uint public closed;
    uint public settled;
    address public closingAddress;
    StandardToken public assetToken;

    struct Participant
    {
        address addr;
        uint deposit;
        uint netted;
        uint transferedAmount;
        uint amount;
        bytes merkleProof;
        bytes32 hashlock;
        bytes32 secret;
        uint expiration;
        address sender;
        uint nonce;
        address asset;
        address recipient;
        bytes32 locksroot;
    }
    Participant[2] public participants; // We only have two participants at all times

    event ChannelOpened(address assetAdr, address participant1, address participant2); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO
    event ChannelSecretRevealed(); //TODO

    /// @dev modifier ensuring that on a participant of the channel can call a function
    modifier inParticipants {
        if (msg.sender != participants[0].addr &&
            msg.sender != participants[1].addr) throw;
        _
    }

    function NettingChannelContract(address assetAdr, address participant1, address participant2, uint lckdTime) {
        assetToken = StandardToken(assetAdr);
        assetAddress = assetAdr;
        participants[0].addr = participant1;
        participants[1].addr = participant2;
        lockedTime = lckdTime;
    }

    /// @notice atIndex(address) to get the index of an address (0 or 1)
    /// @dev get the index of an address
    /// @param addr (address) the address you want the index of
    function atIndex(address addr) private returns (uint index) {
        if (addr == participants[0].addr) return 0;
        else return 1;
    }

    /// @notice deposit(uint) to deposit amount to channel.
    /// @dev Deposit an amount to the channel. At least one of the participants 
    /// must deposit before the channel is opened.
    /// @param amount (uint) the amount to be deposited to the address
    function deposit(uint256 amount) inParticipants {
        if (assetToken.balanceOf(msg.sender) < amount) throw;
        bool s = assetToken.transferFrom(msg.sender, address(this), amount);
        if (s == true) participants[atIndex(msg.sender)].deposit += amount;
        if(isOpen() && opened == 0) open();
    }

    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() private returns (bool) {
        if (closed > 0) throw;
        if (participants[0].deposit > 0 || participants[1].deposit > 0) return true;
        else return false;
    }

    /// @notice open() to set the opened to be the current block and triggers 
    /// the event ChannelOpened()
    /// @dev Sets the value of `opened` to be the value of the current block.
    /// param none
    /// returns none, but changes the value of `opened` and triggers the event ChannelOpened.
    function open() private {
        opened = block.number;
        // trigger event
        ChannelOpened(assetAddress, participants[0].addr, participants[1].addr);
    }

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return p (address) the partner of the calling party
    function partner(address a) private returns (address p) {
        if (a == participants[0].addr) return participants[1].addr;
        else return participants[0].addr;
    }

    /// @notice addrAndDep() to get the addresses and deposits of the participants
    /// @dev get the addresses and deposits of the participants
    /// @return par1 (address) address of one of the participants
    /// @return par2 (address) address of the the other participant
    /// @return dep1 (uint) the deposit of the first participant
    /// @return dep2 (uint) the deposit of the second participant
    function addrAndDep() returns (address par1, uint dep1, address par2, uint dep2) {
        par1 = participants[0].addr;
        dep1 = participants[0].deposit;
        par2 = participants[1].addr;
        dep2 = participants[1].deposit;
    }
}
