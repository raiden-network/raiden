from typing import Any

import click
import gevent
import structlog
from gevent import Greenlet
from gevent.pool import Group

from scenario_player.runner import ScenarioRunner

from .base import Task, get_task_class_for_type

log = structlog.get_logger(__name__)


class SerialTask(Task):
    _name = 'serial'

    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        super().__init__(runner, config, parent, abort_on_fail)
        self._name = config.get('name')

        self._tasks = []
        for _ in range(config.get('repeat', 1)):
            for task in self._config.get('tasks', []):
                for task_type, task_config in task.items():
                    task_class = get_task_class_for_type(task_type)
                    self._tasks.append(
                        task_class(runner=self._runner, config=task_config, parent=self),
                    )

    def _run(self, *args, **kwargs):
        for task in self._tasks:
            task()

    @property
    def _str_details(self):
        name = ""
        if self._name:
            name = f' - {click.style(self._name, fg="blue")}'
        tasks = "\n".join(str(t) for t in self._tasks)
        return f'{name}\n{tasks}'

    @property
    def _urwid_details(self):
        if not self._name:
            return []
        return [
            ' - ',
            ('task_name', self._name),
        ]


class ParallelTask(SerialTask):
    _name = 'parallel'

    def _run(self, *args, **kwargs):
        group = Group()
        for task in self._tasks:
            group.start(Greenlet(task))
        group.join(raise_error=True)


class WaitTask(Task):
    _name = 'wait'

    def _run(self, *args, **kwargs):
        gevent.sleep(self._config)
