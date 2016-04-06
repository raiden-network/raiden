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
        // address addr
        uint deposit;
        Transfer[] lastSentTransfers;
        //Unlocked unlocked;
    }
    mapping(address => Participant) public participants;

    /*Participant[2] participants; // Might make more sense to use an array like this for participants */
                                 /*// since it only holds two.*/

    event ChannelOpened(address assetAdr); // TODO
    event ChannelClosed(); // TODO
    event ChannelSettled(); // TODO

    function NettingContract(address assetAdr) {
        opened = 0;
        closed = 0;
        settled = 0;
        assetAddress = assetAdr;
    }

    /// @notice deposit(address, uint) to deposit amount to a participant.
    /// @dev Deposit an amount to a participating address.
    /// @param addr (address) the address of the receiving party
    /// @param amount (uint) the amount to be deposited to the address
    function deposit(address addr, uint amount) {
        /*if (addr not in participants) throw; // Isn't currently working. Need datastructure for this*/
        /*if (msg.sender.balance < amount) throw;*/
        /*participants[addr].deposit += amount;*/
        /*if(isOpen() && opened != 0) open();*/
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
        // If addr not in participants throw
        // Return the address in participants that is not msg.sender
    }


    /// @notice isOpen() to check if a channel is open
    /// @dev Check if a channel is open and both parties have deposited to the channel
    /// @return open (bool) the status of the channel
    function isOpen() constant returns (bool open) {
        // if closed is not zero
        // and both participants have a 'deposit' value higher than zero
        // return true else false
        if (closed == 0) throw;
        if ()
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
