# -*- coding: utf-8 -*-
import os
import json

from geventwebsocket.server import WebSocketServer
from geventwebsocket.resource import Resource, WebSocketApplication
from geventwebsocket.protocols.wamp import WampProtocol, export_rpc

from raiden.raiden_service import (
    RaidenAPI,
    RaidenService,
    NoPathError,
    InvalidAddress,
    InvalidAmount
)
from raiden.api.wamp_server import WebSocketAPI


# monkey patch: gevent-websocket to support 'extra' argument
class _Resource(Resource):
    def __init__(self, apps=None, extra=None):
        super(_Resource, self).__init__(apps)
        assert type(extra) is dict or None
        if extra is not None:
            self.extra = extra

    def __call__(self, environ, start_response):
        environ = environ
        is_websocket_call = 'wsgi.websocket' in environ
        current_app = self._app_by_path(environ['PATH_INFO'], is_websocket_call)

        if current_app is None:
            raise Exception("No apps defined")

        if is_websocket_call:
            ws = environ['wsgi.websocket']
            extra = self.extra
            # here the WebSocketApplication objects get constructed
            current_app = current_app(ws, extra)
            current_app.ws = ws  # TODO: needed?
            current_app.handle()
            # Always return something, calling WSGI middleware may rely on it
            return []
        else:
            return current_app(environ, start_response)


class _WampProtocol(WampProtocol):
    def __init__(self, *args, **kwargs):
        super(_WampProtocol, self).__init__(*args, **kwargs)

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


class UIHandler(object):
    """ Handles the RPC-calls from the UI and interfaces with the RaidenAPI.
    Forwards publish-messages to the UIService greenlet.
    """
    def __init__(self, raiden, registrars=None):
        assert isinstance(raiden, RaidenService)
        self.api = raiden.api
        self.address = self.api.raiden.address
        assert isinstance(self.api, RaidenAPI)
        self.port = None  # neccessary?
        self.ui_service = None  # neccessary?
        # self.assetmanagers = self.api.raiden.ass
        self.registrars = registrars  # NOTIMPLEMENTED

    @export_rpc
    def transfer(self, asset_address, amount, target, id):
        try:
            amount = int(amount)
        except ValueError:
            self.exception_handler(id, 'INVALID_AMOUNT')
            return False
        # try to forward transfer to API and handle occuring excpetions
        try:
            self.api.transfer(asset_address, amount, target,
                              lambda _, status, id=id: self.transfer_callback(_, status, id))
            # if cb just failes with success==False, then everything was right,except:
            #   - no active channel was found
            #   - or no channel had a high enough distributable (in TransferTask._run())
            return True
        except NoPathError:
            self.exception_handler(id, 'NO_PATH')
            return False
        # except InsufficientBalance:
        #     self.exception_handler(id, 'INSUFFICIENT_FUNDS')
        except InvalidAmount:
            self.exception_handler(id, 'INVALID_AMOUNT')
            return False
        except InvalidAddress as ex:
            if ex.args[1] is 'asset':
                self.exception_handler(id, 'INVALID_ASSET')
            elif ex.args[1] is 'receiver':
                self.exception_handler(id, 'INVALID_TARGET')
            else:
                self.exception_handler(id, 'UNKNOWN')
            return False
        except:
            self.exception_handler(id, 'UNKNOWN')
            # DEBUG:
            raise

    def transfer_callback(self, _, status, id, reason=None):
        data = [id, status, reason]
        # 7 - 'publish'
        message = [7, "http://localhost:{}/raiden#transfer_cb".format(self.port), data]
        self.publish(message)
        # return flag like 'remove callback'?
        return True

    def exception_handler(self, id, reason):
        if not reason:
            reason = 'UNKNOWN'
        self.transfer_callback(None, False, id, reason=reason)

    @export_rpc
    def get_assets(self):
        assets = [asset.encode('hex') for asset in getattr(self.api, 'assets')]
        return assets

    def publish(self, message):
        """ 'message' format:
            [7, "url/raiden#topic", data]
            7 - 'WAMP publish'
        """
        assert type(message) is list and len(message) == 3
        self.ui_service.protocol.pubsub_action(message)


class UIService(WebSocketApplication):
    protocol_class = _WampProtocol

    def __init__(self, ws, extra=None):
        super(UIService, self).__init__(ws)
        if extra is not None:
            self.extra = extra
        self.registrars = self.extra['registrars']
        self.handler = self.extra['handler']
        setattr(self.handler, 'ui_service', self)
        self.raiden_api = self.handler.api
        self.port = self.handler.port

    def register_pubsub(self, topic):
        if isinstance(topic, str):
            self.protocol.register_pubsub(
                "http://localhost:{}/raiden#{}".format(self.port, topic))
        else:
            raise Exception('Topic subscription not supported')

    def on_open(self):
        # register UIHandler object for RPC-calls:
        self.protocol.register_object(
            "http://localhost:{}/raiden#".format(self.port), self.handler)
        # register all PubSub topics:
        for topic in self.registrars:
            self.register_pubsub(topic)
            print 'Publish URI created: /raiden#{}'.format(topic)
        print "WebUI registration completed\n"

    def on_message(self, message):
        # FIXME: handle client reload/reconnect

        print "message: ", message
        if message is None:
            return
        super(UIService, self).on_message(message)

    def on_close(self, reason):
        print "closed"


class WebUI(object):
    """ Wrapping class to start ws/http server. """

    def __init__(self, handler, registrars=None, port=8080):
        self.handler = handler
        self.port = self.handler.port = port
        self.path = os.path.dirname(__file__)
        if registrars is None:
            registrars = ['transfer_cb']
        self.registrars = registrars

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
        path = os.path.join(self.path, 'static/index.html')
        start_response("200 OK", [("Content-Type", "text/html")])
        return open(path).readlines()

    def run(self):
        static_path = os.path.join(self.path, 'static')

        routes = [('^/static/', self.make_static_application('/static/', static_path)),
                  ('^/$', self.serve_index),
                  ('^/ws$', UIService)
                  ]

        data = {'handler': self.handler,  # object
                'registrars': self.registrars  # list of topics
                }
        resource = _Resource(routes, extra=data)

        server = WebSocketServer(("", self.port), resource, debug=True)
        server.serve_forever()

    def stop(self):
        raise NotImplementedError()


class WAMPRouter(object):
    """ Wrapping class to start ws/http server
    """
    def __init__(self, raiden, port, events=None):
        self.path = os.path.dirname(__file__)
        assert isinstance(raiden, RaidenService)
        self.raiden = raiden
        self.port = port
        self.events = events or []  # XXX check syntax

    def make_static_application(self, basepath, staticdir):  # pylint: disable=no-self-use
        def content_type(path):
            """Guess mime-type. """

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

        def not_found(environ, start_response):  # pylint: disable=unused-argument
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

    def serve_index(self, environ, start_response):  # pylint: disable=unused-argument
        path = os.path.join(self.path, 'static/index.html')
        start_response("200 OK", [("Content-Type", "text/html")])
        return open(path).readlines()

    def run(self):
        static_path = os.path.join(self.path, 'static')  # XXX naming

        routes = [
            ('^/static/', self.make_static_application('/static/', static_path)),
            ('^/$', self.serve_index),
            ('^/ws$', WebSocketAPI)
        ]

        data = {
            'raiden': self.raiden,
            'port': self.port,
            'events': self.events
        }

        resource = Resource(routes, extra=data)

        host_port = ('', self.port)
        server = WebSocketServer(
            host_port,
            resource,
            debug=True,
        )
        server.serve_forever()

    def stop(self):
        raise NotImplementedError()
