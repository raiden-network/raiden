import json
import os
import platform
import socket
import ssl
import subprocess
import time
from http.client import HTTPSConnection
from json import JSONDecodeError
from os import PathLike
from typing import IO, Any, Callable, List, Optional, Tuple, Union
from urllib.parse import urlunparse

import structlog
from mirakuru.base import ENV_UUID
from mirakuru.exceptions import AlreadyRunning, ProcessExitedWithError
from mirakuru.http import HTTPConnection, HTTPException, HTTPExecutor as MiHTTPExecutor

T_IO_OR_INT = Union[IO, int]

log = structlog.get_logger(__name__)


class HTTPExecutor(MiHTTPExecutor):
    """ Subclass off mirakuru.HTTPExecutor, which allows other methods than HEAD """

    def __init__(
        self,
        command: Union[str, List[str]],
        url: str,
        status: str = r"^2\d\d$",
        method: str = "HEAD",
        io: Optional[Union[int, Tuple[T_IO_OR_INT, T_IO_OR_INT, T_IO_OR_INT]]] = None,
        cwd: Union[str, PathLike] = None,
        verify_tls: bool = True,
        **kwargs,
    ):
        super().__init__(command, url, status, **kwargs)
        self.method = method
        self.stdio = io
        self.cwd = cwd
        self.verify_tls = verify_tls

    def after_start_check(self):
        """ Check if defined URL returns expected status to a <method> request. """
        try:
            if self.url.scheme == "http":
                conn = HTTPConnection(self.host, self.port)
            elif self.url.scheme == "https":
                ssl_context = None
                if not self.verify_tls:
                    ssl_context = ssl._create_unverified_context()
                conn = HTTPSConnection(self.host, self.port, context=ssl_context)
            else:
                raise ValueError(f'Unsupported URL scheme: "{self.url.scheme}"')

            self._send_request(conn)
            response = conn.getresponse()
            status = str(response.status)

            if not self._validate_response(response):
                return False

            if status == self.status or self.status_re.match(status):
                conn.close()
                return True

        except (HTTPException, socket.timeout, socket.error) as ex:
            log.debug("Executor process not healthy yet", command=self.command, error=ex)
            time.sleep(0.1)
            return False

        return False

    def start(self):
        """
        Reimplements Executor and SimpleExecutor start to allow setting stdin/stdout/stderr/cwd

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
                "shell": self._shell,
                "stdin": stdin,
                "stdout": stdout,
                "stderr": stderr,
                "universal_newlines": True,
                "env": env,
                "cwd": self.cwd,
            }
            if platform.system() != "Windows":
                popen_kwargs["preexec_fn"] = os.setsid
            self.process = subprocess.Popen(command, **popen_kwargs)

        self._set_timeout()

        try:
            self.wait_for(self.check_subprocess)
        except ProcessExitedWithError as e:
            if e.exit_code == 127:
                raise FileNotFoundError(
                    f"Can not execute {command!r}, check that the executable exists."
                ) from e
            else:
                output_file_names = {io.name for io in (stdout, stderr) if hasattr(io, "name")}
                if output_file_names:
                    log.warning("Process output file(s)", output_files=output_file_names)
            raise
        return self

    def running(self) -> bool:
        """ Include pre_start_check in running, so stop will wait for the underlying listener """
        return super().running() or self.pre_start_check()

    def _send_request(self, conn: HTTPConnection):
        conn.request(self.method, self.url.path)

    def _validate_response(self, response):  # pylint: disable=unused-argument,no-self-use
        return True


class JSONRPCExecutor(HTTPExecutor):
    def __init__(
        self,
        command: Union[str, List[str]],
        url: str,
        jsonrpc_method: str,
        jsonrpc_params: Optional[List[Any]] = None,
        status: str = r"^2\d\d$",
        result_validator: Callable[[Any], Tuple[bool, Optional[str]]] = None,
        io: Optional[Union[int, Tuple[T_IO_OR_INT, T_IO_OR_INT, T_IO_OR_INT]]] = None,
        cwd: Union[str, PathLike] = None,
        verify_tls: bool = True,
        **kwargs,
    ):
        super().__init__(command, url, status, "POST", io, cwd, verify_tls, **kwargs)
        self.jsonrpc_method = jsonrpc_method
        self.jsonrpc_params = jsonrpc_params if jsonrpc_method else []
        self.result_validator = result_validator

    def _send_request(self, conn: HTTPConnection):
        req_body = {
            "jsonrpc": "2.0",
            "method": self.jsonrpc_method,
            "params": self.jsonrpc_params,
            "id": repr(self),
        }
        conn.request(
            method=self.method,
            url=urlunparse(self.url),
            body=json.dumps(req_body),
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        )

    def _validate_response(self, response):
        try:
            response = json.loads(response.read())
            error = response.get("error")
            if error:
                log.warning("Executor process: error response", command=self.command, error=error)
                return False
            assert response["jsonrpc"] == "2.0", "invalid jsonrpc version"
            assert "id" in response, "no id in jsonrpc response"
            result = response["result"]
            if self.result_validator:
                result_valid, reason = self.result_validator(result)
                if not result_valid:
                    log.warning(
                        "Executor process: invalid response",
                        command=self.command,
                        result=result,
                        reason=reason,
                    )
                    return False
        except (AssertionError, KeyError, UnicodeDecodeError, JSONDecodeError) as ex:
            log.warning("Executor process: invalid response", command=self.command, error=ex)
            return False
        return True
