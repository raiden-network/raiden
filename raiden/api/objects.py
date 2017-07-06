
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


class TokensList(FlatList):
    pass


class PartnersPerTokenList(FlatList):
    pass


class EventsList(FlatList):
    pass


class Token(object):
    def __init__(self, token_address):
        self.address = token_address


class PartnersPerToken(object):
    def __init__(self, partner_address, channel):
        self.partner_address = partner_address
        self.channel = channel


class Channel(object):
    def __init__(
            self,
            channel_address,
            token_address,
            partner_address,
            settle_timeout,
            reveal_timeout,
            balance,
            state):
        self.channel_address = channel_address
        self.token_address = token_address
        self.partner_address = partner_address
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.balance = balance
        self.state = state


class ChannelNew(object):

    def __init__(self, netting_channel_address, participant1, participant2, settle_timeout):
        self.netting_channel_address = netting_channel_address
        self.participant1 = participant1
        self.participant2 = participant2
        self.settle_timeout = settle_timeout


class ChannelNewBalance(object):

    def __init__(
            self,
            netting_channel_address,
            token_address,
            participant_address,
            new_balance,
            block_number):

        self.netting_channel_address = netting_channel_address
        self.token_address = token_address
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
