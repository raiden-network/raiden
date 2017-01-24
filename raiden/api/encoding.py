
from marshmallow import Schema, SchemaOpts, post_load, post_dump, pre_load
from werkzeug.routing import BaseConverter
from pyethapp.jsonrpc import address_encoder, address_decoder, data_encoder, data_decoder
from webargs import fields, validate

from raiden.api.objects import Event, List, Object, Filter

API_VERSION = '0.9b'


# type converters for the flask routes
class HexAddressConverter(BaseConverter):

    def to_python(self, value):
        value = address_decoder(value)
        return value

    def to_url(self, value):
        value = address_encoder(value)

        return BaseConverter.to_url(value)


class AddressField(fields.Field):

    def _serialize(self, value, attr, obj):
        return address_encoder(value)

    def _deserialize(self, value, attr, obj):
        return address_decoder(value)


class DataField(fields.Field):

    def _serialize(self, value, attr, obj):
        return data_encoder(value)

    def _deserialize(self, value, attr, obj):
        return data_decoder(value)


class NamespaceOpts(SchemaOpts):
    def __init__(self, meta):
        SchemaOpts.__init__(self, meta)
        self.type = getattr(meta, 'type', None)
        self.classifier = getattr(meta, 'classifier', None)
        self.api_version = API_VERSION


class EnvelopedSchema(Schema):
    '''

    e.g.
        {
            'type': 'Event',
            'classifier': 'channel_settled',
            'version': '0.9b',
            'data': {
                'netting_channel_address': '0x624c4a42215d63282b5e3f754d7b3d5e542c3842',
                'block_number': '1'
            },
        }
    '''
    OPTIONS_CLASS = NamespaceOpts

    @pre_load
    def unwrap_envelope(self, data):
        """
        gets called before loading from serialized JSON-Input
        unpacks the envelope
        :param data:
        :return:
        """
        return data['data']

    @post_dump
    def wrap_with_envelope(self, data):
        type = self.opts.type.__name__
        classifier = self.opts.classifier
        api_version = self.opts.api_version
        return {'type': type, 'classifier': classifier, 'version': api_version, 'data': data}

    @post_load
    def make_object(self, data):
        # this will depend on the Schema used, which has it's object class in the class Meta attributes
        baseclass = self.opts.type
        classifier_str = self.opts.classifier
        # baseclass = type_class_mapping[type_str]
        klass = baseclass.get_subclass_from_classifier(classifier_str)
        return klass(**data)


class ListOpts(SchemaOpts):
    """Same as the default class Meta options, but adds "name" and
    "plural_name" options for enveloping.
    """
    def __init__(self, meta):
        SchemaOpts.__init__(self, meta)
        # use 'List' subclass as type if none is provided
        self.type = getattr(meta, 'type')
        self.classifier = getattr(meta, 'classifier')
        self.api_version = API_VERSION


class ListSchema(Schema):
    OPTIONS_CLASS = ListOpts

    @pre_load(pass_many=True)
    def unwrap_envelope(self, data, many):
        # assert many == True  # FIXME what if only one in list?
        return data['data']

    @post_dump(pass_many=True)
    def wrap_with_envelope(self, data, many):
        assert many == True  # FIXME what if only one in list?
        type = self.opts.type.__name__
        classifier = self.opts.classifier
        api_version = self.opts.api_version
        return {'type': type, 'classifier': classifier, 'version': api_version, 'data': data}

    @post_load
    def make_object(self, data):
        baseclass = self.opts.type
        classifier_str = self.opts.classifier
        # get the class to instantiate from the baseclass attribute
        klass = baseclass.get_subclass_from_classifier(classifier_str)
        return klass(list((elem for elem in data))) # TODO checkme


class EventsListSchema(ListSchema):
    class Meta:
        strict = True
        type = List
        classifier = 'events'


class ChannelSchema(EnvelopedSchema):
    channel_address = AddressField(missing=None)
    asset_address = AddressField(required=True, missing=None)
    partner_address = AddressField(required=True, missing=None)
    settle_timeout = fields.Integer(missing=None)
    reveal_timeout = fields.Integer(missing=None)
    amount = fields.Integer(missing=None)
    status = fields.String(missing=None, validate=validate.OneOf(['closed', 'open', 'settled']))

    class Meta:
        strict= True
        type = Object
        classifier = 'channel'


class ChannelListSchema(ListSchema):
    class Meta:
        strict= True
        type = List
        classifier = 'channel'


class AddressFilterSchema(EnvelopedSchema):
    address_type = fields.String(validate=validate.OneOf(['asset_address', 'partner_address']))
    address = AddressField()

    class Meta:
        strict= True
        type = Filter
        classifier = 'address_filter'


class ChannelNewSchema(EnvelopedSchema):
    netting_channel_address = AddressField()
    asset_address = AddressField()
    partner_address = AddressField()
    block_number = fields.Integer()

    class Meta:
        strict = True
        type = Event
        classifier = 'transfer_received'


class AssetAddedSchema(EnvelopedSchema):
    registry_address = AddressField()
    asset_address = AddressField()
    channel_manager_address = AddressField()

    class Meta:
        strict = True
        type = Event
        classifier = 'asset_added'


class ChannelNewBalanceSchema(EnvelopedSchema):
    netting_channel_address = AddressField()
    asset_address = AddressField()
    participant_address = AddressField()
    new_balance = fields.Integer()
    block_number = fields.Integer()

    class Meta:
        strict = True
        type = Event
        classifier = 'channel_new_balance'


class ChannelClosedSchema(EnvelopedSchema):
    netting_channel_address = AddressField()
    closing_address = AddressField()
    block_number = fields.Integer()

    class Meta:
        strict = True
        type = Event
        classifier = 'channel_closed'


class ChannelSettledSchema(EnvelopedSchema):
    netting_channel_address = AddressField()
    block_number = fields.Integer()

    class Meta:
        strict = True
        type = Event
        classifier = 'channel_settled'


class ChannelSecretRevealedSchema(EnvelopedSchema):
    netting_channel_address = AddressField()
    secret = DataField()

    class Meta:
        strict = True
        type = Event
        classifier = 'channel_secret_revealed'



class TransferReceivedSchema(EnvelopedSchema):
    asset_address = AddressField()
    initiator_address = AddressField()
    recipient_address = AddressField()
    transferred_amount = AddressField()
    identifier = fields.Integer()
    hashlock = DataField()

    class Meta:
        strict = True
        type = Event
        classifier = 'transfer_received'



if __name__ == '__main__':

    from raiden.api.objects import ChannelSettled
    from marshmallow import pprint

    # test: this works!!

    obj = ChannelSettled(address_decoder('0x624c4a42215d63282b5e3f754d7b3d5e542c3842'), 100)
    obj2 = ChannelSettled(address_decoder('0x624c4a42215d63282b5e3f754d7b3d5e542c3842'), 1111)

    schema = ChannelSettledSchema()
    ser = schema.dump(obj)
    ser = ser.data
    deser = schema.load(ser)


    # test: TODO fixme

    schema = EventsListSchema()
    ser_iterable = schema.dump([obj, obj2], many=True)
    ser_iterable = ser_iterable.data
    deser_iterable = schema.load(ser_iterable)
    pprint(deser_iterable)


    assert obj == deser # FIXME equality!
