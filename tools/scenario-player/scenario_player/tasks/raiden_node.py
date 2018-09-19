from .execution import ProcessTask


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
