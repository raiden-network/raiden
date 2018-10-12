import shlex
import subprocess

import gevent
import structlog

from scenario_player.exceptions import ScenarioError
from scenario_player.tasks.base import Task

log = structlog.get_logger(__name__)


class ProcessTask(Task):
    _name = 'process'
    _command = ''

    def _run(self, *args, **kwargs):
        if self._runner.is_managed:
            method = getattr(self._runner.node_controller[self._config], self._command)
            method()
        else:
            command = self._runner.node_commands.get(self._command)
            if not command:
                raise ScenarioError(
                    'Invalid scenario definition. '
                    f'The {self._command}_node task requires '
                    f'nodes.commands.{self._command} to be set.',
                )
            command = command.format(self._config)
            log.debug('Command', type_=self._command, command=command)
            greenlet = gevent.spawn(subprocess.run, shlex.split(command), check=True)
            self._handle_process(greenlet)

    def _handle_process(self, greenlet):
        greenlet.join()
        greenlet.get()


class StartNodeTask(ProcessTask):
    _name = 'start_node'
    _command = 'start'

    def _handle_process(self, greenlet):
        # FIXME: Wait for port to become available and then stop blocking on the greenlet
        super()._handle_process(greenlet)


class StopNodeTask(ProcessTask):
    _name = 'stop_node'
    _command = 'stop'


class KillNodeTask(ProcessTask):
    _name = 'kill_node'
    _command = 'kill'
