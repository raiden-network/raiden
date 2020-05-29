import datetime
import logging
import logging.config
import logging.handlers
import os
import re
import sys
from functools import wraps
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Pattern, Tuple

import gevent
import structlog

from raiden.exceptions import ConfigurationError

LOG_BLACKLIST: Dict[Pattern, str] = {
    re.compile(r"\b(access_?token=)([a-z0-9_-]+)", re.I): r"\1<redacted>",
    re.compile(
        r"(@0x[0-9a-fA-F]{40}:(?:[\w\d._-]+(?::[0-9]+)?))/([0-9a-zA-Z-]+)"
    ): r"\1/<redacted>",
    re.compile(r'"secret": ?"0x[0-9a-fA-F]{64}"'): r'"secret": "<redacted>"',
}
DEFAULT_LOG_LEVEL = "INFO"
MAX_LOG_FILE_SIZE = 20 * 1024 * 1024
LOG_BACKUP_COUNT = 3

_FIRST_PARTY_PACKAGES = frozenset(["raiden", "raiden_contracts"])


def _chain(first_func: Callable, *funcs: Callable) -> Callable:
    """Chains a give number of functions.
    First function receives all args/kwargs. Its result is passed on as an argument
    to the second one and so on and so forth until all function arguments are used.
    The last result is then returned.
    """

    @wraps(first_func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
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
    def __init__(self, log_level_config: Dict[str, str], name: str = ""):
        super().__init__(name)
        self._log_filter = LogFilter(log_level_config, default_level=DEFAULT_LOG_LEVEL)

    def filter(self, record: logging.LogRecord) -> int:
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


def redactor(blacklist: Dict[Pattern, str]) -> Callable[[str], str]:
    """Returns a function which transforms a str, replacing all matches for its replacement"""

    def processor_wrapper(msg: str) -> str:
        for regex, replacement in blacklist.items():
            msg = regex.sub(replacement, msg)
        return msg

    return processor_wrapper


def configure_debug_logfile_path(debug_log_file_path: Optional[str]) -> str:
    """Determine the pathname for the debug logfile based on the given argument and user's OS"""

    if debug_log_file_path is not None:
        given_dir = os.path.dirname(debug_log_file_path)
        # If it's not just a filename relative to the current directory make sure
        # that the directory exists
        if given_dir != "" and not os.path.isdir(given_dir):
            raise ConfigurationError(
                f"The provided directory {given_dir} for the debuglog filename "
                f"either does not exist or is not a directory"
            )

        return debug_log_file_path

    # From here and on determine default based on user's system
    time = datetime.datetime.utcnow().isoformat()
    debug_log_file_name = f"raiden-debug_{time}.log"

    home = os.path.expanduser("~")
    if home == "~":  # Could not expand user path, just use /tmp
        datadir = "/tmp"
    if sys.platform == "darwin":
        datadir = os.path.join(home, "Library", "Logs", "Raiden")
    elif sys.platform == "win32" or sys.platform == "cygwin":
        datadir = os.path.join(home, "AppData", "Roaming", "Raiden")
    elif os.name == "posix":
        datadir = os.path.join(home, ".raiden")
    else:
        raise RuntimeError("Unsupported Operating System")

    if not os.path.exists(datadir):
        os.makedirs(datadir)

    return os.path.join(datadir, debug_log_file_name)


def configure_logging(
    logger_level_config: Dict[str, str] = None,
    colorize: bool = True,
    log_json: bool = False,
    log_file: str = None,
    disable_debug_logfile: bool = False,
    debug_log_file_path: str = None,
    cache_logger_on_first_use: bool = True,
    _first_party_packages: FrozenSet[str] = _FIRST_PARTY_PACKAGES,
    _debug_log_file_additional_level_filters: Dict[str, str] = None,
) -> None:
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
        structlog.processors.format_exc_info,
    ]

    if log_json:
        formatter = "json"
    elif colorize and not log_file:
        formatter = "colorized"
    else:
        formatter = "plain"

    redact = redactor(LOG_BLACKLIST)

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
        debug_logfile_path = configure_debug_logfile_path(debug_log_file_path)
        handlers["debug-info"] = {
            "class": "logging.handlers.RotatingFileHandler",
            "filename": debug_logfile_path,
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
                    "processor": _chain(structlog.dev.ConsoleRenderer(colors=False), redact),
                    "foreign_pre_chain": processors,
                },
                "json": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.processors.JSONRenderer(), redact),
                    "foreign_pre_chain": processors,
                },
                "colorized": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.dev.ConsoleRenderer(colors=True), redact),
                    "foreign_pre_chain": processors,
                },
                "debug": {
                    "()": structlog.stdlib.ProcessorFormatter,
                    "processor": _chain(structlog.processors.JSONRenderer(), redact),
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
