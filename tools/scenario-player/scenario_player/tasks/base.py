import importlib
import inspect
import pkgutil
import time
from copy import copy
from datetime import timedelta
from enum import Enum
from typing import Any, TypeVar

import click
import gevent
import structlog

from scenario_player.exceptions import UnknownTaskTypeError
from scenario_player.runner import ScenarioRunner

log = structlog.get_logger(__name__)

NAME_TO_TASK = {}


class TaskState(Enum):
    INITIALIZED = ' '
    RUNNING = '•'
    FINISHED = '✔'
    ERRORED = '✗'


TASK_STATE_COLOR = {
    TaskState.INITIALIZED: '',
    TaskState.RUNNING: click.style('', fg='yellow', reset=False),
    TaskState.FINISHED: click.style('', fg='green', reset=False),
    TaskState.ERRORED: click.style('', fg='red', reset=False),
}

_TASK_ID = 0


class Task:
    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        global _TASK_ID

        _TASK_ID = _TASK_ID + 1
        self.id = str(_TASK_ID)
        self._runner = runner
        self._config = copy(config)
        self._parent = parent
        self._abort_on_fail = abort_on_fail
        self.state = TaskState.INITIALIZED
        self.exception = None
        self.level = parent.level + 1 if parent else 0
        self._start_time = None
        self._stop_time = None

        runner.task_cache[self.id] = self
        runner.task_count += 1
        log.debug('Task initialized', task=self)

    def __call__(self, *args, **kwargs):
        log.info('Starting task', task=self)
        self.state = TaskState.RUNNING
        self._runner.running_task_count += 1
        self._start_time = time.monotonic()
        try:
            return self._run(*args, **kwargs)
        except BaseException as ex:
            self.state = TaskState.ERRORED
            log.exception('Task errored', task=self)
            self.exception = ex
            if self._abort_on_fail:
                raise
        finally:
            self._stop_time = time.monotonic()
            self._runner.running_task_count -= 1
            if self.state is TaskState.RUNNING:
                log.info('Task successful', task=self)
                self.state = TaskState.FINISHED

    def _run(self, *args, **kwargs):
        gevent.sleep(1)

    def __repr__(self):
        return f'<{self.__class__.__name__}: {self._config}>'

    def __str__(self):
        color = TASK_STATE_COLOR[self.state]
        reset = click.termui._ansi_reset_all
        return (
            f'{" " * self.level * 2}- [{color}{self.state.value}{reset}] '
            f'{color}{self.__class__.__name__.replace("Task", "")}{reset}'
            f'{self._duration}{self._str_details}'
        )

    @property
    def urwid_label(self):
        task_state_style = f'task_state_{self.state.name.lower()}'
        duration = self._duration
        label = [
            ('default', '['),
            (task_state_style, self.state.value),
            ('default', '] '),
            (task_state_style, self.__class__.__name__.replace("Task", "")),
        ]
        if duration:
            label.append(('task_duration', self._duration))
        label.extend(self._urwid_details)
        return label

    def __hash__(self) -> int:
        return hash((self._config, self._parent))

    @property
    def _str_details(self):
        return f': {self._config}'

    @property
    def _urwid_details(self):
        return [': ', str(self._config)]

    @property
    def _duration(self):
        duration = 0
        if self._start_time:
            if self._stop_time:
                duration = self._stop_time - self._start_time
            else:
                duration = time.monotonic() - self._start_time
        if duration:
            duration = str(timedelta(seconds=duration))
            return f' ({duration})'
        return ''

    @property
    def done(self):
        return self.state in {TaskState.FINISHED, TaskState.ERRORED}


T_Task = TypeVar('T_Task', bound=Task)


def get_task_class_for_type(task_type) -> T_Task:
    task_class = NAME_TO_TASK.get(task_type)
    if not task_class:
        raise UnknownTaskTypeError(f'Task type "{task_type}" is unknown.')
    return task_class


def register_task(task_name, task):
    global NAME_TO_TASK
    log.debug(f'Registered task: {task_name}')
    NAME_TO_TASK[task_name] = task


def collect_tasks(module):
    # If module is a package, discover inner packages / submodules
    for sub_module in pkgutil.iter_modules([module.__path__._path[0]]):
        _, sub_module_name, _ = sub_module
        sub_module_name = module.__name__ + "." + sub_module_name
        submodule = importlib.import_module(sub_module_name)
        collect_tasks_from_submodule(submodule)


def collect_tasks_from_submodule(submodule):
    for _, member in inspect.getmembers(submodule, inspect.isclass):
        if inspect.ismodule(member):
            collect_tasks(submodule)
            continue
        base_classes = inspect.getmro(member)
        if Task in base_classes and hasattr(member, '_name'):
            register_task(
                member._name,
                member,
            )
