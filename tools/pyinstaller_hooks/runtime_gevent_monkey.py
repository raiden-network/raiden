from gevent.monkey import patch_all  # isort:skip # noqa

patch_all()  # isort:skip # noqa

from raiden.network.transport.matrix.rtc.utils import setup_asyncio_event_loop

setup_asyncio_event_loop()
