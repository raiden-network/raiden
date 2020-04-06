import gevent
import pytest

from raiden.utils.nursery import Janitor


class NurseryException(Exception):
    def __init__(self, exit_code):
        super().__init__(self, exit_code)


def die(timeout: int = 0, exit_code: int = 42):
    gevent.sleep(timeout)
    raise NurseryException(exit_code)


def die_os(timeout: int = 0, exit_code: int = 42):
    return ["python", "-c", f"import time, sys; time.sleep({timeout}); sys.exit({exit_code})"]


def test_nursery_detects_exit_code():
    with pytest.raises(NurseryException):
        with Janitor() as nursery:
            p = nursery.spawn_under_watch(die, timeout=2)
            gevent.joinall({p}, raise_error=True, count=1)


def test_nursery_dectect_exit_code_process():
    with pytest.raises(SystemExit):
        with Janitor() as nursery:
            p = nursery.exec_under_watch(die_os(timeout=2))
            gevent.joinall({p}, raise_error=True, count=1)


def test_nursery_detects_failing_popen():
    with pytest.raises(FileNotFoundError):
        with Janitor() as nursery:
            nursery.exec_under_watch(["nota_valid_program"])
