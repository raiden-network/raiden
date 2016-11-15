# -*- coding: utf-8 -*-
import types
import inspect
import json

from geventwebsocket.resource import WebSocketApplication
from geventwebsocket.protocols.wamp import export_rpc
from geventwebsocket.protocols.wamp import WampProtocol as WampProtocolBase

from raiden.raiden_service import (
    RaidenAPI,
    NoPathError,
    InvalidAddress,
    InvalidAmount
)


class WampProtocol(WampProtocolBase):

    def __init__(self, *args, **kwargs):
        super(WampProtocol, self).__init__(*args, **kwargs)

    def on_message(self, message):
        # FIX: handle when ws is already closed (message is None)
        if message is None:
            return

        data = json.loads(message)

        if not isinstance(data, list):
            raise Exception('incoming data is no list')

        if data[0] == self.MSG_PREFIX and len(data) == 3:
            prefix, uri = data[1:3]
            self.prefixes.add(prefix, uri)

        elif data[0] == self.MSG_CALL and len(data) >= 3:
            return self.rpc_call(data)

        elif data[0] in (self.MSG_SUBSCRIBE, self.MSG_UNSUBSCRIBE,
                         self.MSG_PUBLISH):
            return self.pubsub_action(data)
        else:
            raise Exception("Unknown call")


def register_pubsub_with_callback(func=None):
    if isinstance(func, types.FunctionType):
        func._callback_pubsub = func.__name__ + '_status'  # pylint: disable=protected-access
    return func


class WebSocketAPI(WebSocketApplication):
    """ wraps around the API to support id -> feedback callbacks through PubSub"""
    protocol_class = WampProtocol

    def __init__(self, ws, extra):
        super(WebSocketAPI, self).__init__(ws)
        self.api = extra['raiden'].api
        assert isinstance(self.api, RaidenAPI)
        self.port = extra['port']
        self.event_topics = extra['events']
        self.address = self.api.address  # XXX implement getter in api

    def register_pubsub(self, topic):
        assert isinstance(topic, str)
        url = 'http://localhost:{}/raiden#{}'.format(self.port, topic)
        self.protocol.register_pubsub(url)  # pylint: disable=no-member
        print 'Publish URI created: /raiden#{}'.format(topic)

    def on_open(self):
        # register additional methods from the RaidenAPI instance:
        self._dispatch_additional_instance_methods(self.api)
        # register all additional PubSub topics provided by the config,
        # this is the place where the event topics are defined that don't correspond to
        # a callback event

        url = "http://localhost:{}/raiden#".format(self.port), self
        self.protocol.register_object(url)  # pylint: disable=no-member

        for topic in self.event_topics:
            self.register_pubsub(topic)

        # register all functions in self decorated with @register_callback_pubsub
        # the uri will be the method name suffixed with '_status'
        # e.g. topic for 'transfer()' status will be '#transfer_status'
        for k in inspect.getmembers(self, inspect.ismethod):
            if '_callback_pubsub' in k[1].__dict__:
                self.register_pubsub(k[1]._callback_pubsub)  # pylint: disable=protected-access

        print 'WAMP registration complete\n'

    def on_message(self, message):
        # FIXME: handle client reload/reconnect

        print "message: ", message
        if message is None:
            return
        super(WebSocketAPI, self).on_message(message)

    def on_close(self, reason):  # pylint: disable=unused-argument,arguments-differ
        print "closed"

    # application:
    def status_callback(self, _, status, id, topic, reason=None):
        """
        topic name guidelines:
        'transfer_callb' - for inititated transfers (used in webui-JS)
        """
        # pylint: disable=redefined-builtin, invalid-name

        data = [id, status, reason]

        # 7 - 'publish'
        message = [7, "http://localhost:{}/raiden#{}".format(self.port, topic), data]
        self.publish(message)
        return True

    def callback_with_exception(self, id, topic, reason=None):
        # pylint: disable=redefined-builtin, invalid-name

        if not reason:
            reason = 'UNKNOWN'
        self.status_callback(None, False, id, topic, reason=reason)

    def publish(self, message):
        """ 'message' format:
            [7, "url/raiden#topic", data]
            7 - 'WAMP publish'
        """
        print message
        assert isinstance(message, list) and len(message) == 3
        self.protocol.pubsub_action(message)  # pylint: disable=no-member

    # refactor to API
    @export_rpc
    def get_assets(self):
        assets = [asset.encode('hex') for asset in getattr(self.api, 'assets')]
        return assets

    @export_rpc
    def get_address(self):
        return self.address

    def print_callback(self, status):  # pylint: disable=no-self-use
        print status

    @register_pubsub_with_callback  # noqa
    @export_rpc
    def transfer(self, asset_address, amount, target, callback_id):
        """
        Wraps around the APIs transfer() method to introduce additional
        PubSub and callback features.

        To get access to the raw API method, this method would have to be renamed
        """
        # TODO: check all possible errors and pass them to the WAMP-Protocol
        publish_topic = 'transfer_status'
        try:
            amount = int(amount)
        except ValueError:
            self.callback_with_exception(callback_id, publish_topic, reason='INVALID_AMOUNT')
            return False
        # try to forward transfer to API and handle occuring excpetions
        try:
            self.api.transfer(asset_address, amount, target,
                              lambda _, status, id=callback_id, topic=publish_topic:
                              self.status_callback(_, status, id, topic))
            # self.api.transfer(asset_address, amount, target,callback=self.print_callback)

            # # XXX check id / callback_id naming
            # if cb just failes with success==False, then everything was right,except:
            #   - no active channel was found
            #   - or no channel had a high enough distributable (in TransferTask._run())
            return True
        except NoPathError:
            self.callback_with_exception(callback_id, publish_topic, reason='NO_PATH')
            return False
        # except InsufficientBalance:
        #     self.callback_with_exception(id, 'INSUFFICIENT_FUNDS')
        except InvalidAmount:
            self.callback_with_exception(callback_id, publish_topic, reason='INVALID_AMOUNT')
            return False
        except IndexError as ex:
            self.callback_with_exception(callback_id, publish_topic, reason='INVALID_TARGET')
        except InvalidAddress as ex:
            if ex.args[1] is 'asset':
                self.callback_with_exception(callback_id, publish_topic, reason='INVALID_ASSET')
            elif ex.args[1] is 'receiver':
                self.callback_with_exception(callback_id, publish_topic, reason='INVALID_TARGET')
            else:
                self.callback_with_exception(callback_id, publish_topic, reason='UNKNOWN')
            return False
        except:
            self.callback_with_exception(callback_id, publish_topic, reason='UNKNOWN')
            raise

    def _dispatch_additional_instance_methods(self, instance):  # pylint: disable=invalid-name
        """ dispatches all methods from the api that aren't already defined in WebSocketAPI"""
        # self_methods = set([attr for attr in dir(self) if is_method(self, attr)])
        self_methods = [k[0] for k in inspect.getmembers(self, inspect.ismethod)
                        if '_callback_pubsub' in k[1].__dict__]
        # instance_methods = set([attr for attr in dir(instance) if is_method(instance, attr)])
        instance_methods = [k[0] for k in inspect.getmembers(instance, inspect.ismethod)
                            if '_callback_pubsub' in k[1].__dict__]
        methods_difference = list(set(instance_methods) - set(self_methods))
        map(export_rpc, methods_difference)

        url = 'http://localhost:{}/raiden#'.format(self.port)
        self.protocol.register_object(url, instance)  # XXX check for name collisions


# Tuple index out of range when the receivers address is shorter than 40(?) chars
