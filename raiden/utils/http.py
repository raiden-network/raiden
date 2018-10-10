import os
import platform
import socket
import subprocess

from mirakuru.base import ENV_UUID
from mirakuru.exceptions import AlreadyRunning, ProcessExitedWithError
from mirakuru.http import HTTPConnection, HTTPException, HTTPExecutor as MiHTTPExecutor


class HTTPExecutor(MiHTTPExecutor):
    """ Subclass off mirakuru.HTTPExecutor, which allows other methods than HEAD """

    def __init__(self, *args, method='HEAD', io=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.method = method
        self.stdio = io

    def after_start_check(self):
        """ Check if defined URL returns expected status to a <method> request. """
        try:
            conn = HTTPConnection(self.host, self.port)

            conn.request(self.method, self.url.path)
            status = str(conn.getresponse().status)

            if status == self.status or self.status_re.match(status):
                conn.close()
                return True

        except (HTTPException, socket.timeout, socket.error):
            return False

    def start(self):
        """ Reimplements Executor and SimpleExecutor start by allowing setting stdin/stdout/stderr

        It may break input/output/communicate, but will ensure child output redirects won't
        break parent process by filling the PIPE.
        Also, catches ProcessExitedWithError and raise FileNotFoundError if exitcode was 127
        """
        if self.pre_start_check():
            # Some other executor (or process) is running with same config:
            raise AlreadyRunning(self)

        if self.process is None:
            command = self.command
            if not self._shell:
                command = self.command_parts

            if isinstance(self.stdio, (list, tuple)):
                stdin, stdout, stderr = self.stdio
            else:
                stdin = stdout = stderr = self.stdio
            env = os.environ.copy()
            env[ENV_UUID] = self._uuid
            popen_kwargs = {
                'shell': self._shell,
                'stdin': stdin,
                'stdout': stdout,
                'stderr': stderr,
                'universal_newlines': True,
                'env': env,
            }
            if platform.system() != 'Windows':
                popen_kwargs['preexec_fn'] = os.setsid
            self.process = subprocess.Popen(
                command,
                **popen_kwargs,
            )

        self._set_timeout()

        try:
            self.wait_for(self.check_subprocess)
        except ProcessExitedWithError as e:
            if e.exit_code == 127:
                raise FileNotFoundError(
                    f'Can not execute {command!r}, check that the executable exists.',
                ) from e
            raise
        return self

    def running(self) -> bool:
        """ Include pre_start_check in running, so stop will wait for the underlying listener """
        return super().running() or self.pre_start_check()
