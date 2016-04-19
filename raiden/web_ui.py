from geventwebsocket.server import WebSocketServer
from geventwebsocket.resource import Resource, WebSocketApplication
from geventwebsocket.protocols.wamp import WampProtocol, export_rpc
from raiden.raiden_service import RaidenAPI, RaidenService
from raiden.utils import isaddress
import networkx as nx
import os


#  monkey patch: gevent-websocket to support 'extra' argument
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
        self.assetmanagers = self.api.raiden.assetmanagers
        self.registrars = registrars  # NOTIMPLEMENTED

    @export_rpc
    def transfer(self, asset_address, amount, target, id):
        """
        TODO: include other status messages in callback:
        e.g. 0 ('Failed'), 1 ('Success'), 2 ('address not valid'), 3 ('no path'), ...
        """
        print '\n' + '-' * 10 + 'Transfer requested:' + '-' * 10 + \
              ' \n from: \'{}\' \n to: \'{}\' \n asset: \'{}\' \n amount: {}\n'.format(
                  self.address.encode('hex'), target, asset_address, amount) \
            + '-' * 45 + '\n'
        try:
            target = target.decode('hex')
            valid = isaddress(target)
        except TypeError or not valid:
            print '-' * 10 + 'Error:' + '-' * 14 + '\n \'{}\' is no valid address.\n'.format(
                target) + '-' * 30 + '\n'
            # TODO: publish: 'invalid address format'
            self.transfer_callback(None, False, id)
            return
        amount = int(amount)
        asset_address = asset_address.decode('hex')
        am = self.assetmanagers[asset_address]
        is_node = target in am.channelgraph.G.nodes()
        has_path = nx.has_path(am.channelgraph.G, self.address, target)
        # if receiver address exists and path exists, forward transfer/callback to api
        if is_node and has_path:
            self.api.transfer(asset_address, amount, target,
                              lambda _, status, id=id: self.transfer_callback(_, status, id))
        # else: directly call callback with status=False:
        elif not is_node:
            # TODO: publish: 'address not found'
            print '-' * 35 + '\nAddress {} doesn\'t exist\n'.format(target.encode('hex')) +\
                  '-' * 35
            self.transfer_callback(None, False, id)
        elif not has_path:
            # TODO: publish: 'no path found'
            print '-' * 35 + '\nNo path found connecting to: {}\n'.format(target.encode('hex')) +\
                  '-' * 35
            self.transfer_callback(None, False, id)
        else:
            # unknown error, results in 'Error' status in UI
            self.transfer_callback(None, None, id)

    def transfer_callback(self, _, status, id):
        data = [id, status]
        # 7 - 'publish'
        message = [7, "http://localhost:{}/raiden#transfer_cb".format(self.port), data]
        self.publish(message)

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
    protocol_class = WampProtocol

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
        print "message: ", message
        super(UIService, self).on_message(message)

    def on_close(self, reason):
        print "closed"


class WebUI(object):
    """ Wrapping class to start ws/http server
    """
    def __init__(self, handler, registrars=None, port=8080):
        self.handler = handler
        self.port = self.handler.port = port
        self.path = os.path.dirname(__file__)
        if registrars is None:
            registrars = ['transfer_cb']
        self.registrars = registrars

    def make_static_application(self, basepath, staticdir):
        """Return a WSGI application procedure that will
        serve static files from within the given directory.
        basepath is a prefix that will be removed from
        the requested path and replaced with staticdir to
        get the full file name requested.
        not_found is a WSGI application that will be called if the path
        is not found"""
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
            # either we have a bad path or the path doesn't exist
            # so call the not_found app
            return not_found(environ, start_response)
        return app

    def serve_index(self, environ, start_response):
        path = os.path.join(self.path, 'webui/index.html')
        start_response("200 OK", [("Content-Type", "text/html")])
        return open(path).readlines()

    def run(self):
        static_path = os.path.join(self.path, 'webui')

        routes = [('^/static/', self.make_static_application('/static/', static_path)),
                  ('^/$', self.serve_index),
                  ('^/ws$', UIService)
                  ]

        data = {'handler': self.handler,  # object
                'registrars': self.registrars  # list of topics
                }
        resource = _Resource(routes, extra=data)

        server = WebSocketServer(("", self.port), resource, debug=False)
        server.serve_forever()

    def stop():
        # NOTIMPLEMENTED
        pass
