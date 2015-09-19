import random
from messages import Transfer, MediatedTransfer, LockedTransfer, SecretRequest
import assetmanager as assetmanagermodul
from tasks import TransferTask, ForwardSecretTask
from utils import sha3
import gevent


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
            if not (hashlock or secret):
                secret = sha3(hex(random.getrandbits(256)))
                hashlock = sha3(secret)
            # initiate mediated transfer
            t = TransferTask(self, amount, target, hashlock,
                             expiration=None, originating_transfer=None, secret=secret)
            self.transfertasks[hashlock] = t
            t.start()
            t.join()

    def request_transfer(self, amount, target):
        pass

    def on_transferrequest(self, request):
        # dummy, we accept any request, fixme
        self.transfer(self,
                      amount=request.amount,
                      target=request.sender,
                      hashlock=request.hashlock)

    def on_mediatedtransfer(self, transfer):
        assert isinstance(transfer, MediatedTransfer)
        print "ON MEDIATED TRANSFER", self.raiden
        # apply to channel
        channel = self.assetmanager.channels[transfer.sender]
        channel.register_transfer(transfer)
        if transfer.target == self.raiden.address:
            # transfer received!
            sr = SecretRequest(transfer.lock.hashlock)
            self.raiden.sign(sr)
            self.raiden.send(transfer.initiator, sr)
            t = ForwardSecretTask(self, transfer.lock.hashlock, recipient=transfer.sender)
            self.transfertasks[transfer.lock.hashlock] = t
            t.start()
        else:
            t = TransferTask(self, transfer.lock.amount, transfer.target,
                             transfer.lock.hashlock, originating_transfer=transfer)
            self.transfertasks[transfer.lock.hashlock] = t
            t.start()

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
