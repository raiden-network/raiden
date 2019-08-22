import datetime
import linecache
import logging
import logging.config
import logging.handlers
import os
import re
import sys
from functools import wraps
from traceback import walk_tb
from types import TracebackType
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterator,
    List,
    NamedTuple,
    Optional,
    Pattern,
    Set,
    Tuple,
)

import gevent
import structlog

DEFAULT_LOG_LEVEL = "INFO"
MAX_LOG_FILE_SIZE = 20 * 1024 * 1024
LOG_BACKUP_COUNT = 3

_FIRST_PARTY_PACKAGES = frozenset(["raiden", "raiden_contracts"])


class Redact(NamedTuple):
    pattern: Pattern[str]
    replace: str


LOG_REDACT_PATTERNS = [
    Redact(re.compile(r"\b(access_?token=)([a-z0-9_-]+)", re.I), r"\1<redacted>"),
    Redact(
        re.compile(r"(@0x[0-9a-fA-F]{40}:(?:[\w\d._-]+(?::[0-9]+)?))/([0-9a-zA-Z-]+)"),
        r"\1/<redacted>",
    ),
]


def _chain(first_func, *funcs) -> Callable:
    """Chains a given number of functions.
    First function receives all args/kwargs. Its result is passed on as an argument
    to the second one and so on and so forth until all function arguments are used.
    The last result is then returned.
    """

    @wraps(first_func)
    def wrapper(*args, **kwargs):
        result = first_func(*args, **kwargs)
        for func in funcs:
            result = func(result)
        return result

    return wrapper


def _match_list(module_rule: Tuple[List[str], str], logger_name: str) -> Tuple[int, Optional[str]]:
    logger_modules_split = logger_name.split(".") if logger_name else []

    modules_split: List[str] = module_rule[0]
    level: str = module_rule[1]

    if logger_modules_split == modules_split:
        return sys.maxsize, level
    else:
        num_modules = len(modules_split)
        if logger_modules_split[:num_modules] == modules_split:
            return num_modules, level
        else:
            return 0, None


class LogFilter:
    """ Utility for filtering log records on module level rules """

    def __init__(self, config: Dict[str, str], default_level: str):
        """ Initializes a new `LogFilter`

        Args:
            config: Dictionary mapping module names to logging level
            default_level: The default logging level
        """
        self._should_log: Dict[Tuple[str, str], bool] = {}
        # the empty module is not matched, so set it here
        self._default_level = config.get("", default_level)
        self._log_rules = [
            (logger.split(".") if logger else list(), level) for logger, level in config.items()
        ]

    def _get_log_level(self, logger_name: str) -> str:
        best_match_length = 0
        best_match_level = self._default_level
        for module in self._log_rules:
            match_length, level = _match_list(module, logger_name)

            if match_length > best_match_length and level is not None:
                best_match_length = match_length
                best_match_level = level

        return best_match_level

    def should_log(self, logger_name: str, level: str) -> bool:
        """ Returns if a message for the logger should be logged. """
        if (logger_name, level) not in self._should_log:
            log_level_per_rule = self._get_log_level(logger_name)
            log_level_per_rule_numeric = getattr(logging, log_level_per_rule.upper(), 10)
            log_level_event_numeric = getattr(logging, level.upper(), 10)

            should_log = log_level_event_numeric >= log_level_per_rule_numeric
            self._should_log[(logger_name, level)] = should_log
        return self._should_log[(logger_name, level)]


class RaidenFilter(logging.Filter):
    def __init__(self, log_level_config, name=""):
        super().__init__(name)
        self._log_filter = LogFilter(log_level_config, default_level=DEFAULT_LOG_LEVEL)

    def filter(self, record):
        return self._log_filter.should_log(record.name, record.levelname)


def add_greenlet_name(
    _logger: str, _method_name: str, event_dict: Dict[str, Any]
) -> Dict[str, Any]:
    """Add greenlet_name to the event dict for greenlets that have a non-default name."""
    current_greenlet = gevent.getcurrent()
    greenlet_name = getattr(current_greenlet, "name", None)
    if greenlet_name is not None and not greenlet_name.startswith("Greenlet-"):
        event_dict["greenlet_name"] = greenlet_name
    return event_dict


def redact_secret(original_line: str) -> str:
    redacted = original_line
    for redact in LOG_REDACT_PATTERNS:
        redacted = redact.pattern.sub(redact.replace, redacted)
    return redacted


def format_traceback(exc_traceback: TracebackType) -> Iterator[str]:
    for frame, lineno in walk_tb(exc_traceback):
        filename = frame.f_code.co_filename
        name = frame.f_code.co_name
        line = linecache.getline(filename, lineno).strip()

        yield f'  File "{filename}", line {lineno}, in {name}\n' f"{line}\n"


def format_exception_chain(
    exc_value: BaseException, exc_traceback: Optional[TracebackType], seen: Set[int]
) -> Iterator[str]:
    """Recursively format the chain of exceptions for logging.

    Notes:

    - This does not include the stack locals for compactness;
    - It uses the standard library `linecache` module, but it does not force a
      cache reset, which saves a few system calls and may not show the wrong
      line of code in when the files are being edited;
    - It does not handle exceptions traces larger than the stack depth;
    - It does not handle SyntaxError specially.
    """
    # To avoid infinite recursion each exception is processed only once
    seen.add(id(exc_value))

    cause: Optional[BaseException] = exc_value.__cause__
    context: Optional[BaseException] = exc_value.__context__
    suppress_context: bool = exc_value.__suppress_context__

    if cause is not None and id(cause) not in seen:
        yield from format_exception_chain(cause, cause.__traceback__, seen)
        yield "\nThe above exception was the direct cause of the following exception:\n\n"

    if context is not None and id(context) not in seen and not suppress_context:
        yield from format_exception_chain(context, context.__traceback__, seen)
        yield "\nDuring handling of the above exception, another exception occurred:\n\n"

    if exc_traceback is not None:
        yield "Traceback (most recent call last):\n"
        yield from format_traceback(exc_traceback)

    exc_type = type(exc_value)

    # The standard library handles all exceptions ... this is problematic for
    # our codebase because it can handle GreenletExits while formatting
    # exceptions, so instead of using `BaseException` this is using `Exception`
    try:
        yield f"{exc_type.__qualname__}: {exc_value}"
    except Exception:  # Formatting the exception itself can raise an exception
        yield f"{exc_type.__qualname__}"


def format_exception_and_redact_secrets(
    logger, name, event_dict
):  # pylint: disable=unused-argument
    exc_value: Optional[BaseException] = None

    # likely type of this key is `Union[bool, BaseException]`
    log_exc_info = event_dict.pop("exc_info", None)

    if log_exc_info:
        if isinstance(log_exc_info, BaseException):
            exc_value = log_exc_info
            exc_traceback = log_exc_info.__traceback__
        elif isinstance(log_exc_info, tuple):
            _, exc_value, exc_traceback = log_exc_info
        elif log_exc_info:  # assume bool
            _, exc_value, exc_traceback = sys.exc_info()

    if exc_value:
        seen: Set[int] = set()
        trace = format_exception_chain(exc_value, exc_traceback, seen)

        formated_exception = "".join(redact_secret(line) for line in trace)
        if formated_exception[-1:] == "\n":
            formated_exception = formated_exception[:-1]

        event_dict["exception"] = formated_exception

    return event_dict


def configure_logging(
    logger_level_config: Dict[str, str] = None,
    colorize: bool = True,
    log_json: bool = False,
    log_file: str = None,
    disable_debug_logfile: bool = False,
    debug_log_file_name: str = None,
    cache_logger_on_first_use: bool = True,
    _first_party_packages: FrozenSet[str] = _FIRST_PARTY_PACKAGES,
    _debug_log_file_additional_level_filters: Dict[str, str] = None,
):
    structlog.reset_defaults()

    logger_level_config = logger_level_config or dict()
    logger_level_config.setdefault("filelock", "ERROR")
    logger_level_config.setdefault("", DEFAULT_LOG_LEVEL)

    processors = [
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        add_greenlet_name,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S.%f"),
        structlog.processors.StackInfoRenderer(),
        format_exception_and_redact_secrets,
    ]

    if log_json:
        formatter = "json"
    elif colorize and not log_file:
        formatter = "colorized"
    else:
        formatter = "plain"

    handlers: Dict[str, Any] = dict()
    if log_file:
        handlers["file"] = {
            "class": "logging.handlers.WatchedFileHandler",
            "filename": log_file,
            "level": "DEBUG",
            "formatter": formatter,
            "filters": ["user_filter"],
        }
    else:
        handlers["default"] = {
            "class": "logging.StreamHandler",
            "level": "DEBUG",
            "formatter": formatter,
            "filters": ["user_filter"],
        }

    if not disable_debug_logfile:
        if debug_log_file_name is None:
            time = datetime.datetime.utcnow().isoformat()
            debug_log_file_name = f"raiden-debug_{time}.log"
        handlers["debug-info"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": debug_log_file_name,
            "level": "DEBUG",
            "formatter": "debug",
            "maxBytes": MAX_LOG_FILE_SIZE,
            "backupCount": LOG_BACKUP_COUNT,
            "filters": ["raiden_debug_file_filter"],
        }

    logging.config.dictConfig(
        {
            "version": 1,
            "disable_existing_loggers": False,
            "filters": {
                "user_filter": {"()": RaidenFilter, "log_level_config": logger_level_config},
                "raiden_debug_file_filter": {
                    "()": RaidenFilter,
                    "log_level_config": {
                        "": DEFAULT_LOG_LEVEL,
                        "raiden": "DEBUG",
                        **(_debug_log_file_additional_level_filters or {}),
                    },
                },
            },
            "formatters": {
                "plain": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(
                        structlog.dev.ConsoleRenderer(colors=False), redact_secret
                    ),
                    "foreign_pre_chain": processors,
                },
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.processors.JSONRenderer(), redact_secret),
                    "foreign_pre_chain": processors,
                },
                "colorized": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.dev.ConsoleRenderer(colors=True), redact_secret),
                    "foreign_pre_chain": processors,
                },
                "debug": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.processors.JSONRenderer(), redact_secret),
                    "foreign_pre_chain": processors,
                },
            },
            "handlers": handlers,
            "loggers": {"": {"handlers": handlers.keys(), "propagate": True}},
        }
    )
    structlog.configure(
        processors=processors + [structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=cache_logger_on_first_use,
    )

    # set logging level of the root logger to DEBUG, to be able to intercept
    # all messages, which are then be filtered by the `RaidenFilter`
    structlog.get_logger("").setLevel(logger_level_config.get("", DEFAULT_LOG_LEVEL))
    for package in _first_party_packages:
        structlog.get_logger(package).setLevel("DEBUG")

    # rollover RotatingFileHandler on startup, to split logs also per-session
    root = logging.getLogger()
    for handler in root.handlers:
        if isinstance(handler, logging.handlers.RotatingFileHandler):
            handler.flush()
            if os.stat(handler.baseFilename).st_size > 0:
                handler.doRollover()

    # fix logging of py-evm (it uses a custom Trace logger from logging library)
    # if py-evm is not used this will throw, hence the try-catch block
    # for some reason it didn't work to put this into conftest.py
    try:
        from eth.tools.logging import setup_trace_logging

        setup_trace_logging()
    except ImportError:
        pass
