import logging.config
import structlog
from typing import Dict


DEFAULT_LOG_LEVEL = 'INFO'


def _get_log_handler(formatter, log_file):
    if log_file:
        return {
            'file': {
                'class': 'logging.handlers.WatchedFileHandler',
                'filename': log_file,
                'formatter': formatter,
            },
        }
    else:
        return {
            'default': {
                'class': 'logging.StreamHandler',
                'formatter': formatter,
            },
        }


def configure_logging(
    logger_level_config: Dict[str, str] = None,
    colorize: bool = True,
    log_json: bool = False,
    log_file: str = None,
):
    if logger_level_config is None:
        logger_level_config = {'': DEFAULT_LOG_LEVEL}
    timestamper = structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S")
    pre_chain = [structlog.stdlib.add_log_level, timestamper]
    formatter = 'colorized' if colorize and not log_file else 'plain'
    if log_json:
        formatter = 'json'
    log_handler = _get_log_handler(formatter, log_file)
    logging.config.dictConfig(
        {
            'version': 1,
            'formatters': {
                'plain': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=False),
                    'foreign_pre_chain': pre_chain,
                },
                'json': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.processors.JSONRenderer(),
                    'foreign_pre_chain': pre_chain,
                },
                'colorized': {
                    '()': structlog.stdlib.ProcessorFormatter,
                    'processor': structlog.dev.ConsoleRenderer(colors=True),
                    'foreign_pre_chain': pre_chain,
                },
            },
            'handlers': log_handler,
            'loggers': {
                '': {
                    'handlers': list(log_handler.keys()),
                    'level': logger_level_config.get('', DEFAULT_LOG_LEVEL),
                    'propagate': True,
                },
            },
        },
    )
    structlog.configure(
        processors=[
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            timestamper,
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.stdlib.ProcessorFormatter.wrap_for_formatter,
        ],
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    for logger_name, level_name in logger_level_config.items():
        logging.getLogger(logger_name).setLevel(level_name)
