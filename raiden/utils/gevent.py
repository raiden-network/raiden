import gevent


def _make_greenlet_error_handler(original_handler):
    def handle_error(self, context, type, value, tb):
        if not issubclass(type, self.NOT_ERROR):
            self.handle_system_error(type, value)
    return handle_error


def configure_gevent():
    """
    Configure the gevent `Hub` as follows:

      - Set `SYSTEM_ERROR` to `BaseException` to exit the process on any unhandled exception in
        greenlets.

      - Replace the default gevent Hub's error handler with one that only forwards exception types
        not listed in `NOT_ERROR` to the default implementation.
        This is necessary to avoid DNS resolver errors bubbling up into the event loop.
    """
    hub = gevent.get_hub()

    if getattr(hub, '_patched', False):
        return

    hub.NOT_ERROR = (gevent.GreenletExit,)
    hub.SYSTEM_ERROR = (BaseException,)
    hub.__class__.handle_error = _make_greenlet_error_handler(hub.handle_error)
    hub._patched = True
