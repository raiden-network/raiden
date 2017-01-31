Welcome to the raiden wiki!

# Overview Raiden Classes
-------------------------

##	Asset
	a.	Raiden Perspective: No specification regarding what an Asset is/represents
	b.	Address to a single Smart Contract on-chain

##	RaidenProtocol
	a.	Handles the transport layer communication between nodes
	b.	Notifies RaidenService of network events

##	Raiden Service
	a.	Is running off-chain
	b.	Root class of Raiden
	c.	Exposes the Raiden API for interaction with Raiden
	d.	Needs direct access to a local Blockchain Node
	e.	Manages all routines for interactions on and off-chain
	f.	Maintains a list of AssetManagers
	g.	Each of the maintained AssetManagers is responsible for exactly one Asset.

##	AssetManager
	a.	Is running off-chain
	b.	Is owned by exactly one instance of RaidenService
	c.	Is associated with one single Asset
	d.	Is associated with the ChannelManagerContract on the chain which is responsible for the same single Asset
	e.	Maintains a set of direct channels to other nodes for the single asset it is associated with
	f.	Obtains the list of channels initialization from the ChannelManagerContract on the chain

##	ChannelManagerContract
	a.	Is running on-chain
	b.	Is associated with exactly one Asset
	c.	Maintains a list of on-chain NettingChannelContracts

##	NettingChannelContract
	a.	Is running on-chain
	b.	Is associated with exactly one Asset
	c.	Knows both parties of the channel (on-chain addresses)
	d.	Holds deposits of both parties
	e.	Performs on-chain settlement of a channel

##	TransferManager
	a.	Is running off-chain
	b.	Is responsible for the handling of TransferTasks which represent single transfer between two parties in an off-chain channel
	c.	Can spawn TransferTasks for mediated transfers if no direct channel to the target is open
	d.	Can initiate transfer to a target if a channel with the target of a received transfer is open

##	TransferTask (UML: transfer_activity, transfer_state)
	a.	Is running off-chain
	b.	Asynchronous, network event triggered
	c.	Is associated with AssetManager, TransferManager and RaidenService
	d.	Is associated with exactly on transfer
	e.	Is responsible for finding a path for the transfer it is associated that satisfies
		i.	path is active
		ii.	path has enough funding for the transfer
	f.	Initiates CancelTransfer if no path could be found

##	Transfer
Note: see "core processes" below for sequence description

	a.	Contains nonce, asset, balance, recipient, locksroot [, secret]
	b.	nonce: is a counter to track the sequence of messages. The nonce of own Transfers is updated in the Channel and the partners nonce is updated in the partners local mirror class.
	c.	locksroot: is the root of a merkle tree which records the outstanding locked_amounts with their hashlocks. This allows to keep transfering, although there are locks outstanding. This is because the recipient knows that hashlocked transfers can be settled     once the secret becomes available even, when the peer fails and the balance could not be netted.

##	LockedTransfer
	a.	It signs, that the recipient can claim locked_amount if she knows the secret to hashlock. The locked_amount is not part of the balance but implicit in the locksroot.

##	Channel
	a.	Is running off-chain
	b.	Initiated by the local or the corresponding partner node
	c.	Has one corresponding NettingChannelContract on the chain
	d.	There is at most one Channel  per node-tuple per asset.  That is, (currently) a maximum of two (different) nodes can set up exactly one channel for each asset.
	e.	Maintains the balance and final Transfer with the partner node
	f.	Performs creation and cancellation of transfers
	g.	Maintains list of LockedTransfers (see core processes: Transfers in a Channel)
	h.	Performs claims of LockedTransfers (see core processes: Transfers in a Channel)
		i.	Updates own and partner balance on received and sent transfers


# Core Processes
----------------

## Transfers in a channel
	a.	Types: Transfer, LockedTransfer (Parent class for): MediatedTransfer, CancelTransfer
	b.	Transfers are received as message by the RaidenProtocol instance, forwarded to the RaidenService instance and handed over to the TransferManager for actual processing.
	c.	The TransferManager gets the associated Channel from the AssetManager.
	d.	Each Channel keeps track of Transfers and LockedTransfers.
	e.	Transfers that are sent to the other node (partner node for that channel) are also registered by the local Channel. Hence, a Transfer handed over to the Channel can either be a sent or a received Transfer.
	f.	If a Transfer is received, it is registered by the Channel:
		i.	A received Transfer has to have the correct nonce. The nonce is increased for every received transfer from the partner node. This nonce is maintained in the local mirror class of the Partner. The same counter is maintained by the partner node. The nonce ensures consistency regarding the mutual knowledge of the sequence of Transfers.
		ii.	If the received transfer contains a secret, we can claim the amount that is unlocked by the provided secret and update the balance accordingly.
		iii.	If we received a LockerTransfer, the LockedTransfer is registered.
		iv.	Finally the own balance and the partner's balance are updated according to the allowance (= transfer.balance - self.balance). If the transfer contained a secreted, the allowance is 0 and the balance is updated during the claim process triggered in step ii.
	g.	If a Transfer is sent, it is registered by the Channel:
		i.	Symmetrical to Transfer is received.
		ii.	But: we do not need to verifiy that locksroots are correct.
	h.	Transfers can only be initiated if the current balance of the sending node exceeds the amount to be transferred and the expiration block height has not been reached (the latter is only relevant for LockedTransfers).


## Selected multi-hop Transfer Scenarios
### Normal Transfer
	A to C via B:
	A: Initiator Creates Secret
	A: MediatedTransfer > B
	B: MediatedTransfer > C
	C: SecretRequest > A (implicitly signs, that valid transfer was received)
	A: Secret > C
	C: Secret > B

### CancelTransfer:
	A: Initiator Creates Secret
	A: MediatedTransfer > B
	B: MediatedTransfer > C
	Failure: C cannot establish path to D (e.g. insufficient distributable, no active node)
	C: CancelTransfer > B (levels out balance)
	B: MediatedTransfer > C2
	C2: MediatedTransfer > D

### TimeoutTransfer:
	A: Initiator Creates Secret
	A: MediatedTransfer > B
	B: MediatedTransfer > C
	Failure: No Ack from C
	B: TransferTimeout > A
	Resolution: A won't reveal the secret, tries new transfer, B bans C
