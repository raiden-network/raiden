import gevent

from raiden.exceptions import UnhandledExceptionInGreenlet


class RaidenGreenlet(gevent.Greenlet):
    """
    Custom greenlet class to be used for all greenlets in Raiden.

    Provides `_safe` variants to `gevent.Greenlet`'s `link`, `link_exception` and `rawlink`
    methods. Every callable linked to a greenlet by the `_safe` methods will be wrapped
    to make sure all unhandled exceptions in itself or its greenlet will bubble up to the
    main greenlet.
    """
    def link_safe(self, callable):
        self.is_safe_linked = True
        super().link(self._wrap_linked_callable(callable))

    def link_exception_safe(self, callable):
        self.is_safe_linked = True
        super().link_exception(self._wrap_linked_callable(callable))

    def rawlink_safe(self, callable):
        self.is_safe_linked = True
        super().rawlink(self._wrap_linked_callable(callable))

    @staticmethod
    def _wrap_linked_callable(callable):
        def wrapped_callable(greenlet):
            try:
                callable(greenlet)
            except gevent.get_hub().SYSTEM_ERROR:
                raise
            except Exception as exception:
                raise UnhandledExceptionInGreenlet(exception) from exception
        return wrapped_callable


class RaidenAsyncResult(gevent.event.AsyncResult):
    def rawlink_safe(self, callable):
        self.is_safe_linked = True
        super().rawlink(self._wrap_linked_callable(callable))

    @staticmethod
    def _wrap_linked_callable(callable):
        def wrapped_callable(greenlet):
            try:
                callable(greenlet)
            except gevent.get_hub().SYSTEM_ERROR:
                raise
            except Exception as exception:
                raise UnhandledExceptionInGreenlet(exception) from exception
        return wrapped_callable


class RaidenGreenletEvent(gevent._event.Event):
    def rawlink_safe(self, callable):
        self.is_safe_linked = True
        super().rawlink(self._wrap_linked_callable(callable))

    @staticmethod
    def _wrap_linked_callable(callable):
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
          greenlet, so we know any uncaught exception will be reraised as an
          `UnhandledExceptionInGreenlet` and bubble up.
        - or the exception is listed in NOT_ERROR. This includes DNS resolve errors as well as
          GreenletExit.

      Notice that this breaks the usual `gevent.Greenlet` linking methods. Functions linked via
      `rawlink`, `link` and `link_exception` will not be called if an exception is raised inside
      a Greenlet, the exception will be bubbled up instead.

      This workaround with custom link methods seems unavoidable due to gevent constraints.
      The `gevent.Greenlet` class does not carry sufficient information about links to it. There
      is a `has_links` method but no way to find out which of `link`, `link_exception` etc have
      been called; also `has_links` will often yield `True` without us having linked anything,
      probably due to some internal use of link methods.
    """
    hub = gevent.get_hub()

    if getattr(hub, '_patched', False):
        return

    gevent.spawn = RaidenGreenlet.spawn
    gevent.spawn_later = RaidenGreenlet.spawn_later
    hub._default_system_error = hub.SYSTEM_ERROR
    hub._default_handle_error = hub.__class__.handle_error
    hub.SYSTEM_ERROR = hub.SYSTEM_ERROR + (UnhandledExceptionInGreenlet,)
    hub.__class__.handle_error = _patch_handle_error(hub.__class__.handle_error)
    hub._patched = True


def undo_configure_gevent():
    hub = gevent.get_hub()

    if not getattr(hub, '_patched', False):
        return

    gevent.spawn = gevent.Greenlet.spawn
    gevent.spawn_later = gevent.Greenlet.spawn_later
    hub.SYSTEM_ERROR = hub._default_system_error
    hub.__class__.handle_error = hub._default_handle_error
    hub._patched = False
