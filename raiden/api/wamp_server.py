import os
import json
import types
import inspect

from geventwebsocket.server import WebSocketServer
from geventwebsocket.resource import WebSocketApplication
from geventwebsocket.protocols.wamp import export_rpc

from raiden.patches.geventwebsocket import Resource
from raiden.patches.geventwebsocket import WampProtocol

from raiden.raiden_service import (
    RaidenAPI,
    RaidenService,
    NoPathError,
    InvalidAddress,
    InvalidAmount
)


def register_pubsub_with_callback(func=None):
    if isinstance(func, types.FunctionType):
        func._callback_pubsub = func.__name__ + "_status"
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
        self.protocol.register_pubsub(
            "http://localhost:{}/raiden#{}".format(self.port, topic))
        print 'Publish URI created: /raiden#{}'.format(topic)

    def on_open(self):
        # register additional methods from the RaidenAPI instance:
        self._dispatch_additional_instance_methods(self.api)
        # register all additional PubSub topics provided by the config,
        # this is the place where the event topics are defined that don't correspond to
        # a callback event

        self.protocol.register_object(
            "http://localhost:{}/raiden#".format(self.port), self)

        for topic in self.event_topics:
            self.register_pubsub(topic)
        # register all functions in self decorated with @register_callback_pubsub
        # the uri will be the method name suffixed with '_status'
        # e.g. topic for 'transfer()' status will be '#transfer_status'
        for k in inspect.getmembers(self, inspect.ismethod):
            if '_callback_pubsub' in k[1].__dict__:
                self.register_pubsub(k[1]._callback_pubsub)
        print "WAMP registration complete\n"

    def on_message(self, message):
        # FIXME: handle client reload/reconnect

        print "message: ", message
        if message is None:
            return
        super(WebSocketAPI, self).on_message(message)

    def on_close(self, reason):
        print "closed"

    # application:
    def status_callback(self, _, status, id, topic, reason=None):
        """
        topic name guidelines:
        'transfer_callb' - for inititated transfers (used in webui-JS)
        """
        data = [id, status, reason]
        # 7 - 'publish'
        message = [7, "http://localhost:{}/raiden#{}".format(self.port, topic), data]
        self.publish(message)
        return True

    def callback_with_exception(self, id, topic, reason=None):
        if not reason:
            reason = 'UNKNOWN'
        self.status_callback(None, False, id, topic, reason=reason)

    def publish(self, message):
        """ 'message' format:
            [7, "url/raiden#topic", data]
            7 - 'WAMP publish'
        """
        print message
        assert type(message) is list and len(message) == 3
        self.protocol.pubsub_action(message)

    # refactor to API
    @export_rpc
    def get_assets(self):
        assets = [asset.encode('hex') for asset in getattr(self.api, 'assets')]
        return assets

    @export_rpc
    def get_address(self):
        return self.address

    def print_callback(_, status):
        print status


    @register_pubsub_with_callback
    @export_rpc
    def transfer(self, asset_address, amount, target, callback_id):
        """ wraps around the APIs transfer() method to introduce additional PubSub and callback features
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

    def _dispatch_additional_instance_methods(self, instance):
        """ dispatches all methods from the api that aren't already defined in WebSocketAPI"""
        # self_methods = set([attr for attr in dir(self) if is_method(self, attr)])
        self_methods = [k[0] for k in inspect.getmembers(self, inspect.ismethod)
                        if '_callback_pubsub' in k[1].__dict__]
        # instance_methods = set([attr for attr in dir(instance) if is_method(instance, attr)])
        instance_methods = [k[0] for k in inspect.getmembers(instance, inspect.ismethod)
                            if '_callback_pubsub' in k[1].__dict__]
        methods_difference = list(set(instance_methods) - set(self_methods))
        map(export_rpc, methods_difference)
        self.protocol.register_object(
            "http://localhost:{}/raiden#".format(self.port), instance)  # XXX check for name collisions


class WAMPRouter(object):
    """ Wrapping class to start ws/http server
    """
    def __init__(self, raiden, port, events=None):
        self.path = os.path.dirname(__file__)
        assert isinstance(raiden, RaidenService)
        self.raiden = raiden
        self.port = port
        self.events = events or []  # XXX check syntax

    def make_static_application(self, basepath, staticdir):
        def content_type(path):
            """Guess mime-type
            """

            if path.endswith(".css"):
                return "text/css"
            elif path.endswith(".html"):
                return "text/html"
            elif path.endswith(".jpg"):
                return "image/jpeg"
            elif path.endswith(".js"):
                return "text/javascript"
            else:
                return "application/octet-stream"

        def not_found(environ, start_response):
            start_response('404 Not Found', [('content-type', 'text/html')])
            return ["""<html><h1>Page not Found</h1><p>
                       That page is unknown. Return to
                       the <a href="/">home page</a></p>
                       </html>""", ]

        def app(environ, start_response):
            path = environ['PATH_INFO']
            if path.startswith(basepath):
                path = path[len(basepath):]
                path = os.path.join(staticdir, path)
                if os.path.exists(path):
                    h = open(path, 'r')
                    content = h.read()
                    h.close()
                    headers = [('Content-Type', content_type(path))]
                    start_response("200 OK", headers)
                    return [content, ]
            return not_found(environ, start_response)
        return app

    def serve_index(self, environ, start_response):
        path = os.path.join(self.path, 'webui/index.html')
        start_response("200 OK", [("Content-Type", "text/html")])
        return open(path).readlines()

    def run(self):
        static_path = os.path.join(self.path, 'webui')  # XXX naming

        routes = [('^/static/', self.make_static_application('/static/', static_path)),
                  ('^/$', self.serve_index),
                  ('^/ws$', WebSocketAPI)
                  ]

        data = {'raiden': self.raiden,
                'port': self.port,
                'events': self.events
                }
        resource = Resource(routes, extra=data)

        server = WebSocketServer(("", self.port), resource, debug=True)
        server.serve_forever()

    def stop():
        raise NotImplementedError()

"""
Tuple index out of range when the receivers address is shorter than 40(?) chars
"""
