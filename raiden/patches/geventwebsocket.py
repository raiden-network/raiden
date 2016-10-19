# -*- coding: utf-8 -*-
from __future__ import absolute_import

import json

from geventwebsocket.protocols.wamp import WampProtocol as WampProtocolBase
from geventwebsocket.resource import Resource as ResourceBase


#  monkey patch: gevent-websocket to support 'extra' argument
class Resource(ResourceBase):  # pylint: disable=too-few-public-methods

    def __init__(self, apps=None, extra=None):
        super(Resource, self).__init__(apps)

        assert isinstance(extra, (dict, type(None)))

        if extra is not None:
            self.extra = extra

    def __call__(self, environ, start_response):
        environ = environ
        is_websocket_call = 'wsgi.websocket' in environ
        current_app = self._app_by_path(environ['PATH_INFO'], is_websocket_call)

        if current_app is None:
            raise Exception("No apps defined")

        if is_websocket_call:
            websocket = environ['wsgi.websocket']
            extra = self.extra
            # here the WebSocketApplication objects get constructed
            current_app = current_app(websocket, extra)
            current_app.ws = websocket  # TODO: needed?
            current_app.handle()
            # Always return something, calling WSGI middleware may rely on it
            return []
        else:
            return current_app(environ, start_response)


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
