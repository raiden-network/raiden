from typing import Callable, List, Optional, TypeVar

from astroid.exceptions import InferenceError
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

T = TypeVar("T")

MISSING_ADDRESS_ID = "log-allow-no-node"
MISSING_ADDRESS_MSG = "Please add `node=to_checksum_address(our_address)` in the logging call"
LOGGING_NON_CHECKSUMED_ADDRESS_ID = "log-address-is-checksumed"
LOGGING_NON_CHECKSUMED_ADDRESS_MSG = "Please make sure the address is a checksumed string"
LOGGING_BYTES_ID = "log-allow-binary"
LOGGING_BYTES_MSG = (
    "Do not log a value of type bytes, encode it to a hexadecimal string before logging."
)
LOGGING_RESERVED_NAME_ID = "log-allow-name-reuse"
LOGGING_RESERVED_NAME_MSG = "The name log is reservered for a logging instance"


def is_log_call(expr) -> bool:
    return expr.as_string().startswith("log.")


def is_logger_instance(inferred_value):
    module_name = inferred_value.root().name

    # RootLogger.root().name is just `logging`
    is_stdlib = module_name.startswith("logging")
    is_structlog = module_name.startswith("structlog")
    is_logger = is_stdlib or is_structlog

    return is_logger


def first(elements: List[T], predicate: Callable[[T], bool]) -> Optional[T]:
    for kw in elements:
        if predicate(kw):
            return kw

    return None


def register(linter):
    linter.register_checker(LoggingNodeAddress(linter))


class LoggingNodeAddress(BaseChecker):
    __implements__ = IAstroidChecker

    name = "log-node-address"
    priority = -1
    msgs = {
        "E9492": (MISSING_ADDRESS_MSG, MISSING_ADDRESS_ID, "log is missing the node's address."),
        "E9493": (LOGGING_BYTES_MSG, LOGGING_BYTES_ID, "logging binary value, convert it to hex."),
        "E9494": (
            LOGGING_NON_CHECKSUMED_ADDRESS_MSG,
            LOGGING_NON_CHECKSUMED_ADDRESS_ID,
            "the key node must be a checksumed address.",
        ),
        "E9495": (
            LOGGING_RESERVED_NAME_MSG,
            LOGGING_RESERVED_NAME_ID,
            "log must be a logger instance.",
        ),
    }

    def _check_values_are_not_binary(self, node):
        for kw in node.keywords:
            for value in kw.value.infer():
                if value.pytype() == "builtins.bytes":
                    self.add_message(LOGGING_BYTES_ID, node=node)

    def _check_logger_name(self, node, name, value):
        if name.name != "log":
            return

        # `logging.getLogger` will infer None, Uninferrable, RootLogger
        try:
            has_a_valid_logger = any(
                is_logger_instance(inferred_value) for inferred_value in value.infer()
            )

            if not has_a_valid_logger:
                self.add_message(LOGGING_RESERVED_NAME_ID, node=node)
        except InferenceError:
            self.add_message(LOGGING_RESERVED_NAME_ID, node=node)

    def visit_assignname(self, node):
        try:
            name, value = node.get_children()
        except ValueError:
            pass
        else:
            self._check_logger_name(node, name, value)

    def visit_call(self, node):
        # For a piece of code like the following:
        #
        #   log = structlog.get_logger(__name__)
        #   log.info("Raiden started")
        #
        # Astroid 2.2.5 cannot infer the value of `info`, and there is no
        # reference to the `log` object.
        #
        # To circumvent this problem, the name `log` is force to be the result
        # of a `get_logger` call, and every expression starting with `log.` is
        # assumed to be a logging call.

        if is_log_call(node):
            if not node.keywords:
                self.add_message(MISSING_ADDRESS_ID, node=node)
            else:
                node_keyword = first(node.keywords, lambda el: el.arg == "node")

                if node_keyword is None:
                    self.add_message(MISSING_ADDRESS_ID, node=node)
                else:
                    is_checksum_address = node_keyword.value.as_string().startswith(
                        "to_checksum_address"
                    )

                    if not is_checksum_address:
                        self.add_message(LOGGING_NON_CHECKSUMED_ADDRESS_ID, node=node)

                try:
                    self._check_values_are_not_binary(node)
                except InferenceError:
                    pass
