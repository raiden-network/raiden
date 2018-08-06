import gevent
import pytest

from raiden.exceptions import UnhandledExceptionInGreenlet

from raiden.utils import privtopub, sha3


def test_privtopub():
    privkey = sha3(b'secret')
    pubkey = ('c283b0507c4ec6903a49fac84a5aead951f3c38b2c72b69da8a70a5bac91e9c'
              '705f70c7554b26e82b90d2d1bbbaf711b10c6c8b807077f4070200a8fb4c6b771')

    assert pubkey == privtopub(privkey).hex()


def test_patched_gevent_exception_handling(with_configure_gevent):
    with pytest.raises(_ExceptionInGreenlet):  # exception is bubbled up
        greenlet = gevent.spawn(_exception_raising_greenlet)
        greenlet.join()

    with pytest.raises(_ExceptionInGreenlet):
        greenlet = gevent.spawn_later(0.1, _exception_raising_greenlet)
        greenlet.join()

    try:
        greenlet1 = gevent.spawn(_exception_raising_greenlet)
        greenlet2 = gevent.spawn_later(0.1, _exception_raising_greenlet)
        greenlet3 = gevent.spawn_later(0.1, _exception_raising_greenlet)
        greenlet1.link_exception_safe(_swallow_exception)
        greenlet2.rawlink_safe(_swallow_exception)
        greenlet3.link_safe(_swallow_exception)
        greenlet1.join()
        greenlet2.join()
        greenlet3.join()
    except Exception:
        assert False, 'This should not be propagated out of the greenlet'

    with pytest.raises(UnhandledExceptionInGreenlet, message='_ExceptionInGreenlet (msg)'):
        greenlet = gevent.spawn_later(0.1, _exception_raising_greenlet)
        greenlet.link_exception_safe(_reraise_exception)
        greenlet.join()

    with pytest.raises(UnhandledExceptionInGreenlet, message='_ExceptionInGreenlet (msg)'):
        greenlet = gevent.spawn(_exception_raising_greenlet)
        greenlet.rawlink_safe(_reraise_exception)
        greenlet.join()

    with pytest.raises(UnhandledExceptionInGreenlet, message='_ExceptionInGreenlet (msg)'):
        greenlet = gevent.spawn(_exception_raising_greenlet)
        greenlet.link_safe(_reraise_exception)
        greenlet.join()


class _ExceptionInGreenlet(Exception):
    pass


def _exception_raising_greenlet():
    raise _ExceptionInGreenlet('msg')


def _swallow_exception(greenlet):
    try:
        greenlet.get()
    except _ExceptionInGreenlet:
        pass
    else:
        assert False, 'greenlet.get() did not raise the expected exception.'


def _reraise_exception(greenlet):
    greenlet.get()
