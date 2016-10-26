# -*- coding: utf-8 -*-
import gc
import os

import gevent

from raiden.utils import get_project_root

__all__ = (
    'cleanup_tasks',
)


def get_test_contract_path(contract_name):
    contract_path = os.path.join(
        get_project_root(),
        'tests',
        'smart_contracts',
        contract_name
    )
    return os.path.realpath(contract_path)


def cleanup_tasks():
    tasks = [
        running_task
        for running_task in gc.get_objects()
        if isinstance(running_task, gevent.Greenlet)
    ]
    gevent.killall(tasks)
    gevent.hub.reinit()
