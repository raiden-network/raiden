from messages import Ack, Secret, BaseError, CancelTransfer, TransferTimeout
from messages import Transfer, MediatedTransfer, LockedTransfer
import assetmanager as assetmanagermodul
from tasks import TransferTask


class TransferManager(object):

    """
    mediates transfers, for a fee
    """

    def __init__(self, assetmanager):
        assert isinstance(assetmanager, assetmanagermodul.AssetManager)
        self.raiden = assetmanager.raiden
        self.assetmanager = assetmanager
        self.transfertasks = dict()  # hashlock > TransferTask

    def transfer(self, amount, target, hashlock=None, secret=None):
        if target in self.assetmanager.channels and not hashlock:
            # direct connection
            channel = self.assetmanager.channels[target]
            transfer = channel.create_transfer(amount, secret=secret)
            self.raiden.sign(transfer)
            channel.register_transfer(transfer)
            self.raiden.protocol.send(transfer.recipient, transfer)
        else:
            assert not secret
            assert hashlock  # we need a hashlock sent by target to initiate a mediated transfer
            # initiate mediated transfer
            t = TransferTask(self.assetmanager, amount, target, hashlock)
            self.transfertasks[hashlock] = t
            t.join()

    def request_transfer(self, amount, target):
        pass

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


class ExchangeManager(object):

    """
    collects and forwards exchange requests, for a fee
    semi centralized
    filters, so that only matching exchange requests are delivered
    """
    pass
