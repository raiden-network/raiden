import os
import socket
import subprocess

from mirakuru.base import ENV_UUID
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
        """ Reimplements SimpleExecutor.start by setting stdin/out to None instead of PIPE

        It may break input/output/communicate, but will ensure child output redirects won't
        break parent process
        """
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
            self.process = subprocess.Popen(
                command,
                shell=self._shell,
                stdin=stdin,
                stdout=stdout,
                stderr=stderr,
                universal_newlines=True,
                preexec_fn=os.setsid,
                env=env,
            )

        self._set_timeout()
        return self
