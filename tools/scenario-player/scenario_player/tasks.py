import shlex
import subprocess
import time
from enum import Enum
from typing import Any, TypeVar

import click
import gevent
import structlog
from gevent import Greenlet
from gevent.pool import Group
from requests import RequestException

from scenario_player.exceptions import (
    RESTAPIError,
    ScenarioAssertionError,
    ScenarioError,
    UnknownTaskTypeError,
)
from scenario_player.runner import ScenarioRunner

log = structlog.get_logger(__name__)


class TaskState(Enum):
    INITIALIZED = ' '
    RUNNING = '•'
    FINISHED = '✔'
    ERRORED = '✗'


TASK_STATE_COLOR = {
    TaskState.INITIALIZED: '',
    TaskState.RUNNING: click.style('', fg='yellow', reset=False),
    TaskState.FINISHED: click.style('︎', fg='green', reset=False),
    TaskState.ERRORED: click.style('', fg='red', reset=False),
}


class Task:
    def __init__(
        self,
        runner: ScenarioRunner,
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        self._runner = runner
        self._config = config
        self._parent = parent
        self._abort_on_fail = abort_on_fail
        self.state = TaskState.INITIALIZED
        self.exception = None
        self.level = parent.level + 1 if parent else 0
        self._start_time = None
        self._stop_time = None

        runner.task_count += 1
        log.info('Task initialized', task=self)

    def __call__(self, *args, **kwargs):
        log.info('Starting task', task=self)
        self.state = TaskState.RUNNING
        self._runner.running_task_count += 1
        self._start_time = time.monotonic()
        try:
            return self._run(*args, **kwargs)
        except Exception as ex:
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
    def _str_details(self):
        return f': {self._config}'

    @property
    def _duration(self):
        duration = 0
        if self._start_time:
            if self._stop_time:
                duration = self._stop_time - self._start_time
            else:
                duration = time.monotonic() - self._start_time
        if duration:
            return f' [{duration:3.0f} s]'
        return ''


class SerialTask(Task):
    def __init__(
        self,
        runner: 'ScenarioRunner',
        config: Any,
        parent: 'Task' = None,
        abort_on_fail=True,
    ) -> None:
        super().__init__(runner, config, parent, abort_on_fail)

        self._tasks = []
        for _ in range(config.get('repeat', 1)):
            for task in self._config.get('tasks', []):
                for task_type, task_config in task.items():
                    task_class = _get_task_class_for_type(task_type)
                    self._tasks.append(
                        task_class(runner=self._runner, config=task_config, parent=self),
                    )

    def _run(self, *args, **kwargs):
        for task in self._tasks:
            task()

    @property
    def _str_details(self):
        tasks = "\n".join(str(t) for t in self._tasks)
        return f'\n{tasks}'


class ParallelTask(SerialTask):
    def _run(self, *args, **kwargs):
        group = Group()
        for task in self._tasks:
            group.start(Greenlet(task))
        group.join(raise_error=True)


class RaidenAPIActionTask(Task):
    _name = ''
    _url_template = ""
    _method = 'get'

    @property
    def _request_params(self):
        return {}

    @property
    def _url_params(self):
        return {}

    @property
    def _target_host(self):
        return self._runner.raiden_nodes[self._config['from']]

    def _process_response(self, response: dict):
        return response

    def _run(self, *args, **kwargs):
        url = self._url_template.format(
            protocol=self._runner.protocol,
            target_host=self._target_host,
            **self._url_params,
        )
        try:
            resp = self._runner.session.request(self._method, url, json=self._request_params)
        except RequestException as ex:
            raise RESTAPIError(f'Error performing REST-API call: {self._name}') from ex
        if not 199 < resp.status_code < 300:
            raise RESTAPIError(f'Status {resp.status_code} while fetching {url}: {resp.text}')
        try:
            return self._process_response(resp.json())
        except (ValueError, UnicodeDecodeError) as ex:
            raise RESTAPIError(
                f'Error decoding response for url {url}: {resp.status_code} {resp.text}',
            ) from ex


class OpenChannelTask(RaidenAPIActionTask):
    _name = 'open_channel'
    _url_template = '{protocol}://{target_host}/api/1/channels'
    _method = 'put'

    @property
    def _request_params(self):
        params = dict(
            token_address=self._runner.token_address,
            partner_address=self._runner.node_to_address[
                self._runner.raiden_nodes[
                    self._config['to']
                ]
            ],
        )
        total_deposit = self._config.get('total_deposit')
        if total_deposit:
            params['total_deposit'] = total_deposit
        return params


class ChannelActionTask(RaidenAPIActionTask):
    _url_template = '{protocol}://{target_host}/api/1/channels/{token_address}/{partner_address}'
    _method = 'patch'

    @property
    def _url_params(self):
        return dict(
            token_address=self._runner.token_address,
            partner_address=self._runner.node_to_address[
                self._runner.raiden_nodes[
                    self._config['to']
                ]
            ],
        )


class CloseChannelTask(ChannelActionTask):
    _name = 'close_channel'

    @property
    def _request_params(self):
        return dict(state='closed')


class DepositTask(ChannelActionTask):
    _name = 'deposit'

    @property
    def _request_params(self):
        return dict(total_deposit=self._config['total_deposit'])


class TransferTask(ChannelActionTask):
    _name = 'transfer'
    _url_template = '{protocol}://{target_host}/api/1/payments/{token_address}/{partner_address}'
    _method = 'post'

    @property
    def _request_params(self):
        return dict(amount=self._config['amount'])


class WaitTask(Task):
    def _run(self, *args, **kwargs):
        gevent.sleep(self._config)


class AssertTask(ChannelActionTask):
    _name = 'assert'
    _method = 'get'

    def _process_response(self, response: dict):
        for field in ['balance', 'total_deposit', 'state']:
            if field not in self._config:
                continue
            if field not in response:
                raise ScenarioAssertionError(f'Field "{field}" is missing in channel: {response}')
            if response[field] != self._config[field]:
                raise ScenarioAssertionError(
                    f'Value mismatch for "{field}". '
                    f'Should: "{self._config[field]}" '
                    f'Is: "{response[field]}" '
                    f'Channel: {response}',
                )


class ProcessTask(Task):
    _command = ''

    def _run(self, *args, **kwargs):
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
    _command = 'start'

    def _handle_process(self, greenlet):
        # FIXME: Wait for port to become available and then stop blocking on the greenlet
        super()._handle_process(greenlet)


class StopNodeTask(ProcessTask):
    _command = 'stop'


class KillNodeTask(ProcessTask):
    _command = 'kill'


NAME_TO_TASK = {
    'serial': SerialTask,
    'parallel': ParallelTask,
    'open_channel': OpenChannelTask,
    'close_channel': CloseChannelTask,
    'deposit': DepositTask,
    'transfer': TransferTask,
    'wait': WaitTask,
    'assert': AssertTask,
    'stop_node': StopNodeTask,
    'start_node': StartNodeTask,
    'kill_node': KillNodeTask,
}


T_Task = TypeVar('T_Task', bound=Task)


def _get_task_class_for_type(task_type) -> T_Task:
    task_class = NAME_TO_TASK.get(task_type)
    if not task_class:
        raise UnknownTaskTypeError(f'Task type "{task_type}" is unknown.')
    return task_class
