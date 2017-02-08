
class FlatList(list):
    """
    This class inherits from list and has the same interface as a list-type.
    However, there is a 'data'-attribute introduced, that is required for the encoding of the list!
    The fields of the encoding-Schema must match the fields of the Object to be encoded!
    """

    @property
    def data(self):
        return list(self)

    def __repr__(self):
        return '<{}: {}>'.format(self.__class__.__name__, list(self))


class ChannelList(FlatList):
    pass


class EventsList(FlatList):
    pass


class Channel(object):
    def __init__(self, channel_address, asset_address, partner_address, settle_timeout, reveal_timeout, deposit, status):
        self.channel_address = channel_address
        self.asset_address = asset_address
        self.partner_address = partner_address
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.deposit = deposit
        self.status = status


class TransferReceived(object):
    def __init__(self, asset_address, recipient_address, initiator_address, transferred_amount, hashlock, identifier):
        self.asset_address = asset_address,
        self.recipient_address = recipient_address,
        self.initiator_address = initiator_address,
        self.transferred_amount = transferred_amount,
        self.hashlock = hashlock
        self.identifier = identifier


class AssetAdded(object):

    def __init__(self, registry_address, asset_address, channel_manager_address):
        self.registry_address = registry_address
        self.asset_address = asset_address
        self.channel_manager_address = channel_manager_address


class ChannelNew(object):

    def __init__(self, netting_channel_address, participant1, participant2, settle_timeout):
        self.netting_channel_address = netting_channel_address
        self.participant1 = participant1
        self.participant2 = participant2
        self.settle_timeout = settle_timeout


class ChannelNewBalance(object):

    def __init__(self, netting_channel_address, asset_address, participant_address, new_balance, block_number):
        self.netting_channel_address = netting_channel_address
        self.asset_address = asset_address
        self.participant_address = participant_address
        self.new_balance = new_balance
        self.block_number = block_number


class ChannelClosed(object):

    def __init__(self, netting_channel_address, closing_address, block_number):
        self.netting_channel_address = netting_channel_address
        self.closing_address = closing_address
        self.block_number = block_number


class ChannelSettled(object):

    def __init__(self, netting_channel_address, block_number):
        self.netting_channel_address = netting_channel_address
        self.block_number = block_number


class ChannelSecretRevealed(object):

   def __init__(self, netting_channel_address, secret):
        self.netting_channel_address = netting_channel_address
        self.secret = secret
