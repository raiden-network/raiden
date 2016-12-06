import inspect
import types

from flask import Flask
import socketio
import gevent
from werkzeug.routing import BaseConverter


"""
This is the server for the API exposure. All methods marked by the @expose decorator will be available via http-requests
at the given REST endpoint, once the Dispatcher is initialized and the server is running.
Synchronous methods will return their return-value immediately in the request's respond message.
Asynchronous methods will not return their return value, but rather a unique callback-id, that will later be used in a 'rpc_response'
Event via socket.io for evaluation.

The response is structured like this:

{
    callback_id: value or None if Synchronous
    method= str (the methods name)
    result= value or None if Asynchronous
}

Clients should also connect to the websocket that is used for push-Notifications ('Events') via the socket.io protocol.
Without the connection to the socket, asynchronous calls over http-requests will be initiated, but the client has no knowledge
about the success of the call.
Also externally initiated state-updates such as channel-opening or incoming transfers will not be observed by the client,
if he doesn't want to pull this information constantly.

Events are structured like this:

    Event:      'rpc_response'
    namespace:  '/'
    data:       {
                    callback_id: <int>,
                    procedure: <str>,
                    status: <bool>
                }

"""

try:
    import ujson as json
except ImportError:
    try:
        import simplejson as json
    except ImportError:
        import json



class MethodMisconstructionError(Exception):
    pass

def expose(route, methods, async=False):
    def _expose(func):
        func._expose = {'route': route}
        func._expose['methods'] = methods
        if async==True and not 'callback' in inspect.getargspec(func).args:
            raise MethodMisconstructionError(func)
        func._expose['async'] = async
        func._expose['name'] = func.__name__
        return func
    return _expose


def serialize(data):
    return json.dumps(data)


def deserialize(msg):
    return json.loads(msg)


class RemoteProcedure(object):

    def __init__(self, procedure, callback=None):
        self.procedure = procedure # this is expected to be an raiden api method
        self.call_count = 0
        self.callback = callback
        if self.is_async:
            assert isinstance(callback, types.FunctionType)

    @property
    def is_async(self):
        return self.procedure._expose['async']

    @property
    def name(self):
        return self.procedure._expose['name']

    def __call__(self, *args, **kwargs):
        if self.is_async:
            call_id = hash(self.name + str(self.call_count))
            # TODO should we use something like a hash or a simple counter?
            # to consider: should it be easily reproducible in the client?

            def callback(_, status, id_=call_id):
                self.callback(_, status, id_)

            # create or overwrite callback kwarg)
            try:
                kwargs['callback']
            except KeyError:
                kwargs['callback'] = callback
            # else:
            #     log Warning, callback provided, default callback not used


            # spawn method, but don't pass result, it could be unserializable
            gevent.spawn(self.procedure, *args, **kwargs)

            # All async methods should only return the method name
            result =  serialize(dict(callback_id=call_id, method=self.name, result=None))
        else:
            # all sync methods should return a serializable value
            # TODO review of serialization
            result =  serialize(dict(callback_id=None, method=self.name, result=self.procedure(*args, **kwargs)))

        self.call_count += 1
        return result


class Dispatcher(object): #name?
    def __init__(self, flask_app, socketio):
        self.calls = {}
        self.events = {}  # TODO
        self.app = flask_app
        self.sio = socketio


    @property
    def registered_procedures(self):
        return self.calls.keys()

    def register_procedure(self, proc):
        if inspect.isfunction(proc) or inspect.ismethod(proc):
            callback = None
            if proc._expose['async']==True:
                callback = self.callback_factory(proc._expose['name'])

            self.calls[proc._expose['name']] = RemoteProcedure(
                proc,
                callback=callback
            )

            # add the flask route and map to the dispatcher internally
            self.app.add_url_rule(
                proc._expose['route'],
                proc._expose['name'],
                lambda func_name=proc._expose['name'], *args, **kwargs: self.call(func_name, *args, **kwargs),
                methods=proc._expose['methods']
            )
        else:
            raise Exception(proc)

    def register_api(self, api):
        for k in inspect.getmembers(api, inspect.ismethod):
            proc = k[1]
            if '_expose' in proc.__dict__:
                self.register_procedure(proc)
            # else:
            #     TODO log 'procedure {proc} not marked for api exposure'

    def callback_factory(self, proc_name, namespace=None):
        def callback( _, status, id, procedure=proc_name, namespace=namespace):
            data = dict(callback_id = id, procedure=procedure, status=status)
            self.sio.emit('rpc_callback', data, namespace=namespace, )
        return callback

    def call(self, func_name, *args, **kwargs):
        if func_name in self.calls:
            proc = self.calls[func_name]
            assert isinstance(proc, RemoteProcedure)
            return proc(*args, **kwargs)
        else:
            raise Exception("Method '{}' not dispatchable".format(func_name))



# type converters for the flask routes

class HexAddressConverter(BaseConverter):

    def to_python(self, value):
        # TODO: check for length and validity
        # Allow 0x and different formatting etc
        # decoding is done in the API method
        return value

    def to_url(self, value):
        return BaseConverter.to_url(value)


def register_type_converters(app):
    app.url_map.converters['address'] = HexAddressConverter


app = Flask(__name__)
register_type_converters(app)

sio = socketio.Server(logger=True, async_mode='gevent')
