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
