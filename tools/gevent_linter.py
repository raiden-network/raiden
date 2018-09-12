__version__ = '0.0.1'


class CodingChecker:
    name = 'flake8_raiden_gevent'
    version = __version__

    def __init__(self, _tree, filename):
        self.filename = filename

    def read_file(self):
        if self.filename in ('stdin', '-', None):
            try:
                # flake8 >= v3.0
                from flake8.engine import pep8 as stdin_utils
            except ImportError:
                from flake8 import utils as stdin_utils
            return stdin_utils.stdin_get_value().splitlines(True)

        try:
            import pycodestyle
        except ImportError:
            import pep8 as pycodestyle
        return pycodestyle.readlines(self.filename)

    def run(self):
        try:
            lines = self.read_file()

            for lineno, line in enumerate(lines, start=1):
                if 'gevent.spawn' in line and '=' not in line:
                    msg = (
                        "greenlet from gevent.spawn is being forgotten! "
                        "always handle child greenlets"
                    )
                    yield lineno, 0, msg, type(self)

                if 'gevent.joinall' in line and 'raise_error=True' not in line:
                    yield lineno, 0, "gevent.joinall must always re-raise", type(self)
        except IOError:
            pass
