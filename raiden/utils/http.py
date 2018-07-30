import socket
from mirakuru.http import HTTPExecutor as MiHTTPExecutor, HTTPConnection, HTTPException


class HTTPExecutor(MiHTTPExecutor):
    """ Subclass off mirakuru.HTTPExecutor, which allows other methods than HEAD """

    def __init__(self, *args, method='HEAD', **kwargs):
        super().__init__(*args, **kwargs)
        self.method = method

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
