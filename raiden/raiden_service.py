import rlp
import messages
from messages import Ack, HashLock, BaseError, CancelTransfer, TransferTimeout
from messages import Transfer, MediatedTransfer, LockedTransfer
from channelgraph import ChannelGraph
from utils import privtoaddr, isaddress, pex, sha3
from contracts import NettingChannelContract, ChannelManagerContract
import channel
import gevent
from gevent.event import AsyncResult


class RaidenProtocol(object):

    """
    each message sent or received is stored by hash
    if message is received twice, resent previous answer
    if there is no response to a message, message gets repeated max N times
    """

    try_interval = 1.
    max_tries = 3
    max_message_size = 1200

    def __init__(self, transport, discovery, raiden_service):
        self.transport = transport
        self.discovery = discovery
        self.raiden_service = raiden_service

        self.tries = dict()  # msg hash: count_tries
        self.sent_acks = dict()  # msghash: Ack

    def send(self, receiver_address, msg):
        assert isaddress(receiver_address)
        assert not isinstance(msg, (Ack, BaseError))

        host_port = self.discovery.get(receiver_address)
        msghash = msg.hash
        self.tries[msghash] = self.max_tries
        data = rlp.encode(msg)
        assert len(data) < self.max_message_size
        while self.tries.get(msghash, 0) > self.max_tries:
            assert self.tries[msghash] == self.max_tries,  "DEACTIVATED MSG resents"
            self.transport.send(self.raiden_service, host_port, data)
            gevent.sleep(self.try_interval)
            self.tries -= 1

    def send_ack(self, receiver_address, msg):
        assert isinstance(msg,  (Ack, BaseError))
        assert isaddress(receiver_address)
        host_port = self.discovery.get(receiver_address)
        self.transport.send(self.raiden_service, host_port, rlp.encode(msg))
        self.sent_acks[msg.echo] = (receiver_address, msg)

    def receive(self, data):
        assert len(data) < self.max_message_size

        # check if we handled this message already, if so repeat Ack
        h = sha3(data)
        if h in self.sent_acks:
            assert False, "DEACTIVATED ACK RESENTS"
            return self.send(*self.sent_acks[h])

        # note, we ignore the sending endpoint, as this can not be known w/ UDP
        msg = messages.deserialize(data)
        # handle Acks
        if isinstance(msg, Ack):
            del self.tries[msg.echo]

        assert isinstance(msg, HashLock) or msg.sender
        self.raiden_service.on_message(msg)


class ExchangeService(object):

    """
    collects and forwards exchange requests, for a fee
    semi centralized
    filters, so that only matching exchange requests are delivered
    """
    pass


class AssetManager(object):

    """
    class which handles services for one asset
    """

    def __init__(self, raiden, asset_address):
        assert isinstance(raiden, RaidenService)
        assert isaddress(asset_address)
        self.raiden = raiden
        self.asset_address = asset_address
        self.channels = dict()  # receiver : Channel

        # create channels for contracts
        channelmanager = raiden.chain.channelmanager_by_asset(asset_address)
        assert isinstance(channelmanager, ChannelManagerContract)
        for netting_contract in channelmanager.nettingcontracts_by_address(raiden.address):
            self.add_channel(netting_contract)

        # create network graph for contract
        self.channelgraph = ChannelGraph(channelmanager)

        # TransferManager for asset
        self.transfermanager = TransferManager(self)

    def add_channel(self, contract):
        assert isinstance(contract, NettingChannelContract)
        partner = contract.partner(self.raiden.address)
        self.channels[partner] = channel.Channel(self.raiden, contract)

    def channel_isactive(self, address):
        network_activity = True  # fixme
        return network_activity and self.channels[address].isopen

    @classmethod
    def get_assets_for_address(cls, chain, address):
        "get all assets for which there is a netting channel"
        asset_addresses = []
        for asset_address in chain.asset_addresses:
            channelmanager = chain.channelmanager_by_asset(asset_address)
            assert isinstance(channelmanager, ChannelManagerContract)
            if channelmanager.nettingcontracts_by_address(address):
                asset_addresses.append(asset_address)
        return asset_addresses


class TransferTask(gevent.Greenlet):

    block_expiration = 120  # FIXME, this needs to timeout on block expiration
    timeout_per_hop = 10

    def __init__(self, transfermanager, amount, target, hashlock,
                 expiration=None, originating_transfer=None):  # fee!
        self.transfermanager = transfermanager
        self.assetmanager = transfermanager.assetmanager
        self.raiden = transfermanager.assetmanager.raiden
        self.amount = amount
        self.target = target
        self.hashlock = hashlock
        self.expiration = None or 10  # fixme
        self.originating_transfer = originating_transfer  # no sender == self initiated transfer

    def _run(self):
        # look for shortest path
        for path in self.assetmanager.channelgraph.get_paths(self.raiden.address, self.target):
            assert path[0] == self.raiden.address
            assert path[1] in self.assetmanager.channels
            assert path[-1] == self.target
            recipient = path[1]
            # check if channel is active
            if not self.assetmanager.channel_isactive(recipient):
                continue
            channel = self.assetmanager.channels[recipient]
            # check if we have enough funds ,fixme add limit per transfer
            if self.amount > channel.distributable:
                continue
            # calculate fee, calc expiration
            t = channel.create_lockedtransfer(self.amount, self.expiration, self.hashlock)
            t.to_mediatedtransfer(self.target, fee=0, initiator_signature=None)  # fixme
            channel.register_transfer(t)
            # send mediated transfer
            msg = self.send_transfer(t, path)
            if isinstance(msg, CancelTransfer):
                continue  # try with next path
            elif isinstance(msg, TransferTimeout):
                # stale hashlock
                self.raiden.send(channel.partner.address, msg)
                return False
            elif isinstance(msg, HashLock):
                return True
        # we did not find a path, send CancelTransfer
        if self.originating_transfer:
            channel = self.assetmanager.channels[self.originating_transfer.sender]
            t = channel.create_canceltransfer(self.originating_transfer)
            channel.register_transfer(t)
            self.raiden.send(channel.partner.address, t)
        return False

    def on_event(self, msg):
        assert self.event and not self.event.ready()
        self.event.add(msg)

    def send_transfer(self, transfer, path):
        self.event = AsyncResult()  # http://www.gevent.org/gevent.event.html
        self.raiden.protocol.send(transfer)
        timeout = self.timeout_per_hop * (len(path) - 1)  # fixme, consider no found paths
        msg = self.event.wait(timeout)
        if msg is None:  # timeout
            return TransferTimeout(echo=transfer.hash, hashlock=transfer.hashlock)
        assert msg.hashlock == transfer.hashlock
        channel = self.assetmanager.channels[msg.recipient]
        if isinstance(msg, CancelTransfer):
            assert msg.amount == transfer.amount
            assert msg.recipient == transfer.sender == self.raiden.address
            channel.register_transfer(msg)
            return msg
            # try with next path
        elif isinstance(msg, TransferTimeout):
            assert msg.echo == transfer.hash
            return msg
            # send back StaleHashLock, we need new hashlock
        elif isinstance(msg, HashLock):
            # done exit
            assert msg.hashlock == sha3(msg.secret)
            channel.claim_locked(msg.secret)
            return msg
        assert False, "Not Implemented"


class TransferManager(object):

    """
    mediates transfers, for a fee
    """

    def __init__(self, assetmanager):
        assert isinstance(assetmanager, AssetManager)
        self.raiden = assetmanager.raiden
        self.assetmanager = assetmanager
        self.transfertasks = dict()  # hashlock > TransferTask

    def transfer(self, amount, target, hashlock=None, secret=None):
        if target in self.assetmanager.channels and not hashlock:
            # direct connection
            channel = self.assetmanager.channels[target]
            transfer = channel.create_transfer(amount, secret=secret)
            channel.register_transfer(transfer)
            self.raiden.protocol.send(transfer)
        else:
            assert not secret
            assert hashlock  # we need a hashlock sent by target to initiate a mediated transfer
            # initiate mediated transfer
            t = TransferTask(self.assetmanager, amount, target, hashlock)
            self.transfertasks[hashlock] = t
            t.join()

    def on_transferrequest(self, request):
        # dummy, we accept any request
        self.transfer(self,
                      amount=request.amount,
                      target=request.sender,
                      hashlock=request.hashlock)

    def on_mediatedtransfer(self, transfer):
        # apply to channel
        channel = self.assetmanager.channels[transfer.sender]
        channel.register_transfer(transfer)
        t = TransferTask(self.assetmanager, transfer.amount, transfer.target,
                         transfer.hashlock, originating_transfer=transfer)
        self.transfertasks[transfer.hashlock] = t
        t.join()

    def on_transfer(self, transfer):
        # apply to channel
        assert isinstance(transfer, (Transfer, LockedTransfer))
        channel = self.assetmanager.channels[transfer.sender]
        channel.register_transfer(transfer)

    def on_exchangerequest(self, message):
        # if matches any own order
        # if signed for me and fee:
            # broadcast
        pass


class RaidenAPI(object):

    """
    the external interface to the service
    """

    def __init__(self, raiden):
        self.raiden = raiden

    @property
    def assets(self):
        return self.raiden.assetmanagers.keys()

    def transfer(self, asset_address, amount, target):
        assert isaddress(asset_address) and isaddress(target)
        assert asset_address in self.assets
        tm = self.raiden.assetmanagers[asset_address].transfermanager
        assert isinstance(tm, TransferManager)
        tm.transfer(amount, target)

    def exchange(self, asset_A, asset_B, amount_A=None, amount_B=None, callback=None):
        pass


class RaidenService(object):

    def __init__(self, chain, privkey, transport, discovery):
        self.chain = chain
        self.privkey = privkey
        self.address = privtoaddr(privkey)
        self.protocol = RaidenProtocol(transport, discovery, self)
        self.assetmanagers = dict()

    def setup_assets(self):
        # create asset managers
        for asset_address in AssetManager.get_assets_for_address(self.chain, self.address):
            self.assetmanagers[asset_address] = AssetManager(self, asset_address)

    def on_message(self, msg):
        method = 'on_%s' % msg.__class__.__name__.lower()
        # update activity monitor (which also does pings to all addresses in channels)
        try:
            getattr(self, method)(msg)
        except messages.BaseError as error:
            self.protocol.send_ack(error)
        else:
            self.send_ack(msg)

    def send_ack(self, msg):
        self.protocol.send_ack(msg.sender, messages.Ack(msg.hash).sign(self.address))

    def on_baseerror(self, msg):
        pass

    def on_ping(self, msg):
        pass  # ack already sent, activity monitor should have been notified in on_message

    def on_transfer(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_tranfer(msg)

    on_lockedtransfer = on_transfer

    def on_mediatedtransfer(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_mediatedtransfer(msg)

    # events, that need to find a TransferTask

    def on_event_for_transfertask(self, msg):
        for am in self.assetmanagers.values():
            if msg.hashlock in am.transfermanager.transfertasks:
                am.transfermanager.transfertasks[msg.hashlock].on_event(msg)
                break

    on_hashlock = on_transfertimeout = on_canceltransfer = on_event_for_transfertask

    def on_transferrequest(self, msg):
        am = self.assetmanagers[msg.asset]
        am.transfermanager.on_tranferrequest(msg)

    # other

    def on_rejected(self, msg):
        pass

    def on_hashlockrequest(self, msg):
        pass

    def on_exchangerequest(self, msg):
        pass
