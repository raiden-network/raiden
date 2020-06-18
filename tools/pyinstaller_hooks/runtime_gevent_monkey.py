from gevent.monkey import patch_all  # isort:skip # noqa

patch_all()  # isort:skip # noqa

import asyncio  # isort:skip # noqa
from raiden.network.transport.matrix.rtc import aiogevent  # isort:skip # noqa

asyncio.set_event_loop_policy(aiogevent.EventLoopPolicy())  # isort:skip # noqa
