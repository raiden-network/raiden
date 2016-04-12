contract NettingContract {
    uint lockedTime;
    address assetAddress;
    uint opened;
    uint closed;
    uint settled;

    struct Transfer {} // TODO
    struct Unlocked {} // TODO
    struct Participant
    {
        address addr;
        uint deposit;
        Transfer[] lastSentTransfers;
        //Unlocked unlocked;
    }
    /*mapping(address => Participant) public participants;*/
    Participant[2] participants; // We only have two participants at all times

    event ChannelOpened(address assetAdr); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO

    function NettingContract(address assetAdr) {
        opened = 0;
        closed = 0;
        settled = 0;
        assetAddress = assetAdr;
    }

    function atIndex(address addr) returns (uint index) {
        if (addr == participants[0].addr) return 0;
        if (addr == participants[1].addr) return 1;
    }

    /// @notice deposit(address, uint) to deposit amount to a participant.
    /// @dev Deposit an amount to a participating address.
    /// @param addr (address) the address of the receiving party
    /// @param amount (uint) the amount to be deposited to the address
    function deposit(uint amount) {
        if (msg.sender != participants[0].addr && 
            msg.sender != participants[1].addr) throw;
        if (msg.sender.balance < amount) throw;
        participants[atIndex(msg.sender)].deposit += amount;
        // update balance of sender?
        msg.sender.balance -= amount;
        if(isOpen() && opened == 0) open();
    }


    /// @notice open() to set the opened to be the current block and triggers 
    /// the event ChannelOpened()
    /// @dev Sets the value of `opened` to be the value of the current block.
    /// param none
    /// returns none, but changes the value of `opened` and triggers the event ChannelOpened.
    function open() {
        opened = block.number;

        // trigger event
        ChannelOpened(assetAddress);
    }

    /// @notice partner() to get the partner or other participant of the channel
    /// @dev Get the other participating party of the channel
    /// @return p (address) the partner of the calling party
    function partner() constant returns (address p) {
        if (msg.sender == participants[0].addr) return participants[1].addr;
        else return participants[0].addr;
    }


    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() constant returns (bool open) {
        if (closed == 0) throw;
        if (participants[0].deposit > 0 && participants[1].deposit > 0) return true;
        else return false;
    }


    /// @notice close(Transfer, unlocked[]) to close a channel between to parties
    /// @dev Close the channel between two parties
    /// @param transfer (Transfer) the last sent transfer of the msg.sender
    /// @param unlckd (Unlocked) the struct containing locked data (a bit uncertain about this)
    //function close(Transfer[] lastSentTransfers, Unlocked unlckd) {


        // trigger event
        /*ChannelClosed();*/
    //}


    /// @notice settle() to settle the balance between the two parties
    /// @dev Settles the balances of the two parties fo the channel
    /// @return participants (Participant[]) the participants with netted balances
    //function settle() returns (Participant[] participants) {


        // trigger event
        /*ChannelSettled();*/
    //}


    // empty function to handle wrong calls
    function () { throw; }
}
