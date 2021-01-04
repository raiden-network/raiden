from astroid.exceptions import InferenceError
from astroid.scoped_nodes import Module
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

JOINALL_RAISE_ERROR_ID = "gevent-joinall-raise-error"
JOINALL_RAISE_ERROR_MSG = (
    "`joinall` should always re-raise exceptions from the underlying greenlets, "
    "otherwise errors can be lost and the program will continue in an "
    "undertermined state."
)
GROUP_DISABLE_WAIT_ID = "gevent-disable-wait"
GROUP_DISABLE_WAIT_MSG = (
    "Just calling `gevent.wait` hides errors, since exceptions that killed the "
    "underlying greenlet are swallowed. Instead "
    "`gevent.joinall(raise_error=True)` should be used"
)
GROUP_JOIN_ID = "gevent-group-join"
GROUP_JOIN_MSG = (
    "When calling `Group.join` or `Pool.join` the flag `raise_error` must be set to "
    "`True`, otherwise exceptions will go unoticed."
)
INPUT_FORBIDDEN_ID = "gevent-input-forbidden"
INPUT_FORBIDDEN_MSG = (
    "`input` is a global function, therefore it can not be monkeypatched, "
    "calling this function will block not only the thread using `input()` but "
    "also the event loop, effectively bringing the process to a halt until input "
    "is given, this is usually not the intended behavior."
)
SYS_STDFDS_FORBIDDEN_ID = "gevent-sys-stdfds-forbidden"
SYS_STDFDS_FORBIDDEN_MSG = (
    "gevent does not monkey patch the `sys.std(io,err,out)`, this means these "
    "interfaces must not be directly used otherwise the event loop will be "
    "halted."
)

FD_FORBIDDEN_METHODS = (
    "write",
    "read",
    "flush",
    "truncate",
)
STDFDS = (
    "stdin",
    "stdout",
    "stderr",
)


def is_sys_module(node):
    try:
        for inferred in node.infer():
            if isinstance(inferred, Module) and inferred.name == "sys":
                return True
    except InferenceError:
        pass

    return False


def is_sys_io(node):
    # This detect usages of the form:
    # >>> import sys
    # >>> sys.stdin.read()
    try:
        return (
            node.func.attrname in FD_FORBIDDEN_METHODS
            and node.func.expr.attrname in STDFDS
            and is_sys_module(node.func.expr.expr)
        )
    except AttributeError:
        pass

    # This detect usages of the form:
    # >>> from sys import stdin
    # >>> stdin.read()
    try:
        scope = node.func.expr.scope()
        _, import_from = scope.lookup(node.func.expr.name)
        return (
            node.func.attrname in FD_FORBIDDEN_METHODS
            and node.func.expr.name in STDFDS
            and any(imp.modname == "sys" for imp in import_from)
        )
    except AttributeError:
        pass

    return False


def is_input(inferred_func):
    return inferred_func.name == "input" and inferred_func.callable()


def is_gevent_joinall(inferred_func):
    return (
        inferred_func.name == "joinall"
        and inferred_func.callable()
        and inferred_func.root().name.startswith("gevent")
    )


def is_gevent_wait(inferred_func):
    """Note that `wait` is an alias to wait_on_objects set in the __init__.py,
    the inferred_func will have the original name instead of the alias name.
    """
    return (
        inferred_func.name == "wait_on_objects"
        and inferred_func.callable()
        and inferred_func.root().name.startswith("gevent")
    )


def is_group_join(inferred_func):
    # This intetionally does not check the class, as of gevent 1.5a3 it matches
    # Group and Pool, which are the classes that need to be checked.
    return (
        inferred_func.name == "join"
        and inferred_func.callable()
        and inferred_func.root().name == "gevent.pool"
    )


def is_of_type(inferred_value, type_):
    return inferred_value is type_


def register(linter):
    linter.register_checker(GeventChecker(linter))


class GeventChecker(BaseChecker):
    __implements__ = IAstroidChecker

    name = "gevent"
    priority = -1
    msgs = {
        "E6493": (
            GROUP_JOIN_MSG,
            GROUP_JOIN_ID,
            "Waiting with Group.join without raise_error set to True.",
        ),
        "E6495": (
            GROUP_DISABLE_WAIT_MSG,
            GROUP_DISABLE_WAIT_ID,
            "gevent.wait should not be used, use gevent.joinall(raise_error=True) instead.",
        ),
        "E6496": (
            JOINALL_RAISE_ERROR_MSG,
            JOINALL_RAISE_ERROR_ID,
            "`gevent.joinall` always need `raise_error=True` set.",
        ),
        "E6497": (
            INPUT_FORBIDDEN_MSG,
            INPUT_FORBIDDEN_ID,
            "The global `input()` must not be called since it blocks the event loop.",
        ),
        "E6498": (
            SYS_STDFDS_FORBIDDEN_MSG,
            SYS_STDFDS_FORBIDDEN_ID,
            "The stdout, stderr, and stdin are not cooperative and must not be used directly.",
        ),
    }

    def visit_call(self, node):
        """Called on expressions of the form `expr()`, where `expr` is a simple
        name e.g. `f()` or a path e.g. `v.f()`.
        """
        try:
            self._force_joinall_to_raise_error(node)
        except InferenceError:
            pass

        try:
            self._force_joinall_instead_of_wait(node)
        except InferenceError:
            pass

        try:
            self._force_group_join_to_set_raise_error(node)
        except InferenceError:
            pass

        try:
            self._forbid_calls_to_input(node)
        except InferenceError:
            pass

        try:
            self._forbid_usage_of_sys_file_descriptors(node)
        except InferenceError:
            pass

    def _force_joinall_to_raise_error(self, node):
        """This detect usages of the form:

            >>> from gevent import joinall
            >>> joinall(..., raise_error=True)

        or:

            >>> import gevent
            >>> gevent.joinall(..., raise_error=True)
        """
        for inferred_func in node.func.infer():
            if is_gevent_joinall(inferred_func):
                is_raise_error_true = False

                # This check won't work with positional arguments, which should
                # be fine, since `pool.join(None, True)` is not very readable.
                if node.keywords is not None:
                    is_raise_error_true = any(
                        keyword.arg == "raise_error" and keyword.value.value is True
                        for keyword in node.keywords
                    )

                if not is_raise_error_true:
                    self.add_message(JOINALL_RAISE_ERROR_ID, node=node)

    def _force_joinall_instead_of_wait(self, node):
        """This detect usages of the form:

            >>> from gevent import joinall
            >>> joinall(..., raise_error=True)

        or:

            >>> import gevent
            >>> gevent.joinall(..., raise_error=True)
        """
        for inferred_func in node.func.infer():
            if is_gevent_wait(inferred_func):
                self.add_message(GROUP_DISABLE_WAIT_ID, node=node)

    def _force_group_join_to_set_raise_error(self, node):
        """This detect usages of the form:

        >>> from gevent.pool import Group, Pool
        >>> g = Group()
        >>> g.join(...)
        >>> p = Pool()
        >>> p.join(...)
        """
        for inferred_func in node.func.infer():
            if is_group_join(inferred_func):
                is_raise_error_true = False

                # This check won't work with positional arguments, which should
                # be fine, since `pool.join(None, True)` is not very readable.
                if node.keywords is not None:
                    is_raise_error_true = any(
                        keyword.arg == "raise_error" and keyword.value.value is True
                        for keyword in node.keywords
                    )

                if not is_raise_error_true:
                    self.add_message(JOINALL_RAISE_ERROR_ID, node=node)

    def _forbid_calls_to_input(self, node):
        """This detect usages of the form:

        >>> input()
        """
        for inferred_func in node.func.infer():
            if is_input(inferred_func):
                self.add_message(INPUT_FORBIDDEN_ID, node=node)

    def _forbid_usage_of_sys_file_descriptors(self, node):
        """This detect usages of the form:

        >>> import sys
        >>> sys.stdin.read()

        >>> from sys import stdin
        >>> stdin.read()
        """
        if is_sys_io(node):
            self.add_message(SYS_STDFDS_FORBIDDEN_ID, node=node)
