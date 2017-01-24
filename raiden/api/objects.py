from raiden.utils import snake_to_camel_case


def subclass_from_classifier(cls, classifier):
    # classifiers are specified as the snake_case of the CamelCased class-name:
    search_name = snake_to_camel_case(classifier)
    found_class = None
    for klass in cls.__subclasses__():
        name = klass.__name__
        if name == search_name:
            found_class = klass
            break

    return found_class


# BASE:
# (mostly for namespacing in the Encoding)

class List(list):
    """
    __init__(**events) will initialise the list!
    """

    @classmethod
    def get_subclass_from_classifier(cls, classifier):
        return subclass_from_classifier(cls, classifier)


class Event(object):
    """
    Namespacing for the 'type'and 'classifier' (see raiden.api.encoding.NameSpaceSchema)
    """

    @classmethod
    def get_subclass_from_classifier(cls, classifier):
        return subclass_from_classifier(cls, classifier)


class Object(object):

    @classmethod
    def get_subclass_from_classifier(cls, classifier):
        return subclass_from_classifier(cls, classifier)


class Filter(object):
    @classmethod
    def get_subclass_from_classifier(cls, classifier):
        return subclass_from_classifier(cls, classifier)


# OTHER


class Result(object):
    def __init__(self, successful, data):
        self.successful = successful
        self.data = data # TODO arbitrary nested data, again enveloped!


class AddressFilter(object):

    def __init__(self, address_type, address):
        self.address_type = address_type
        self.address = address


class Channel(object):
    def __init__(self, channel_address, asset_address, partner_address, settle_timeout, reveal_timeout, amount, status):
        self.channel_address = channel_address
        self.asset_address = asset_address
        self.partner_address = partner_address
        self.settle_timeout = settle_timeout
        self.reveal_timeout = reveal_timeout
        self.amount = amount
        self.status = status


class ChannelList(list):
    pass


# EVENTS


class Events(List):
    pass


class TransferReceived(Event):
    def __init__(self, asset_address, initiator_address, recipient_address, transferred_amount, identifier, hashlock=None):
        self.asset_address = asset_address,
        self.initiator_address = initiator_address,
        self.recipient_address = recipient_address,
        self.transferred_amount = transferred_amount,
        self.identifier = identifier


class AssetAdded(Event):

    def __init__(self, registry_address, asset_address, channel_manager_address):
        self.registry_address = registry_address
        self.asset_address = asset_address
        self.channel_manager_address = channel_manager_address


class ChannelNew(Event):

    def __init__(self, netting_channel_address, asset_address, partner_address, block_number):
        self.netting_channel_address = netting_channel_address
        self.asset_address = asset_address
        self.partner_address = partner_address
        self.block_number = block_number


class ChannelNewBalance(Event):

    def __init__(self, netting_channel_address, asset_address, participant_address, new_balance, block_number):
        self.netting_channel_address = netting_channel_address
        self.asset_address = asset_address
        self.participant_address = participant_address
        self.new_balance = new_balance
        self.block_number = block_number


class ChannelClosed(Event):

    def __init__(self, netting_channel_address, closing_address, block_number):
        self.netting_channel_address = netting_channel_address
        self.closing_address = closing_address
        self.block_number = block_number



class ChannelSettled(Event):

    def __init__(self, netting_channel_address, block_number):
        self.netting_channel_address = netting_channel_address
        self.block_number = block_number



class ChannelSecretRevealed(Event):

   def __init__(self, netting_channel_address, secret):
        self.netting_channel_address = netting_channel_address
        self.secret = secret



# HACK just to have easy access to the base Classes from outside:
type_class_mapping = {
    'Event': Event,
    'List': List,
    'Object': Object,
    'Filter': Filter
}