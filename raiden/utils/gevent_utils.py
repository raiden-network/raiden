import gevent

from raiden.exceptions import UnhandledExceptionInGreenlet


class RaidenGreenlet(gevent.Greenlet):
    def link_safe(self, callable):
        self.is_safe_linked = True
        super(RaidenGreenlet, self).link(self._wrap_link(callable))

    def link_exception_safe(self, callable):
        self.is_safe_linked = True
        super(RaidenGreenlet, self).link_exception(self._wrap_link(callable))

    def rawlink_safe(self, callable):
        self.is_safe_linked = True
        super(RaidenGreenlet, self).rawlink(self._wrap_link(callable))

    @staticmethod
    def _wrap_link(callable):
        def wrapped_callable(greenlet):
            try:
                callable(greenlet)
            except gevent.get_hub().SYSTEM_ERROR:
                raise
            except Exception as exception:
                raise UnhandledExceptionInGreenlet(exception) from exception
        return wrapped_callable


def _patch_handle_error(original_handler):
    def patched_handle_error(self, context, type, value, tb):
        safe_linked = getattr(gevent.getcurrent(), 'is_safe_linked', False)
        if safe_linked or issubclass(type, self.NOT_ERROR):
            original_handler(self, context, type, value, tb)
        else:
            self.print_exception(context, type, value, tb)
            self.handle_system_error(type, value)
    return patched_handle_error


def configure_gevent():
    """
    Configure the gevent `Hub` as follows:

      - Patch the `handle_error` method to bubble up any uncaught exception to the main greenlet,
        with two restrictions: We stick to the default error handling if
        - any of `link_exception_safe`, `link_safe` or `rawlink_safe` have been called on the
          greenlet, we expect all Exceptions to be taken care of and stick to the default
          behavior. Uncaught exceptions in the linked functions themselves will raise a
          `RaidenFatalError`
        - or the exception is listed in NOT_ERROR. This includes DNS resolve errors as well as
          GreenletExit.

      Notice that this breaks the usual `gevent.Greenlet` linking methods. Functions linked via
      `rawlink`, `link` and `link_exception` will not be called if an exception is raised inside
      a Greenlet, the exception will be bubbled up instead.
    """
    hub = gevent.get_hub()

    if getattr(hub, '_patched', False):
        return

    gevent.spawn = RaidenGreenlet.spawn
    gevent.spawn_later = RaidenGreenlet.spawn_later
    hub.SYSTEM_ERROR = hub.SYSTEM_ERROR + (UnhandledExceptionInGreenlet,)
    hub.__class__.handle_error = _patch_handle_error(hub.__class__.handle_error)
    hub._patched = True
