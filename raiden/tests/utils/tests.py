# -*- coding: utf8 -*-
import gc

import gevent

__all__ = (
    'cleanup_tasks',
)


def cleanup_tasks():
    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet)
    ]
    gevent.killall(tasks)
