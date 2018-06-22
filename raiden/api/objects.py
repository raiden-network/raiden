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


class AddressList(FlatList):
    pass


class PartnersPerTokenList(FlatList):
    pass


class Address:
    def __init__(self, token_address):
        self.address = token_address


class PartnersPerToken:
    def __init__(self, partner_address, channel):
        self.partner_address = partner_address
        self.channel = channel


class Channel:
    def __init__(
            self,
            channel_address,
            token_address,
            partner_address,
            settle_timeout,
            reveal_timeout,
            balance,
            state,
    ):
        self.channel_address = channel_address
        self.token_address = token_address
        self.partner_address = partner_address
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.balance = balance
        self.state = state
