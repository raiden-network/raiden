from astroid.exceptions import InferenceError
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

JOINALL_ID = "gevent-joinall"
JOINALL_MSG = (
    "First argument of joinall must have type set to avoid deadlocks. NOTE: set "
    "comprehensions are false positives, use `set(<generator>)` instead."
)
GROUP_JOIN_ID = "gevent-group-join"
GROUP_JOIN_MSG = (
    "When calling `Group.join` or `Pool.join` the flag `raise_error` must be set to "
    "`True`, otherwise exceptions will go unoticed."
)


def is_gevent_joinall(inferred_func):
    return (
        inferred_func.name == "joinall"
        and inferred_func.callable()
        and inferred_func.root().name.startswith("gevent")
    )


def is_join(inferred_func):
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
        "E6491": (JOINALL_MSG, JOINALL_ID, "Waiting with joinall on a non set is an error."),
        "E6493": (
            GROUP_JOIN_MSG,
            GROUP_JOIN_ID,
            "Waiting with Group.join without raise_error set to True.",
        ),
    }

    def visit_call(self, node):
        """Called on expressions of the form `expr()`, where `expr` is a simple
        name e.g. `f()` or a path e.g. `v.f()`.
        """
        try:
            self._force_joinall_to_use_set(node)
        except InferenceError:
            pass

        try:
            self._force_group_join_to_set_raise_error(node)
        except InferenceError:
            pass

    def _force_group_join_to_set_raise_error(self, node):
        """This detect usages of the form:

            >>> from gevent.pool import Group, Pool
            >>> g = Group()
            >>> g.join(...)
            >>> p = Pool()
            >>> p.join(...)
        """
        for inferred_func in node.func.infer():
            if is_join(inferred_func):
                is_raise_error_true = False

                # This check won't work with positional arguments, which should
                # be fine, since `pool.join(None, True)` is not very readable.
                if node.keywords is not None:
                    is_raise_error_true = any(
                        keyword.arg == "raise_error" and keyword.value.value is True
                        for keyword in node.keywords
                    )

                if not is_raise_error_true:
                    self.add_message(JOINALL_ID, node=node)

    def _force_joinall_to_use_set(self, node):
        """This detect usages of the form:

            >>> from gevent import joinall
            >>> joinall(...)

        or:

            >>> import gevent
            >>> gevent.joinall(...)
        """
        for inferred_func in node.func.infer():
            if is_gevent_joinall(inferred_func):

                try:
                    is_every_value_a_set = all(
                        inferred_first_arg.pytype() == "builtins.set"
                        for inferred_first_arg in node.args[0].infer()
                    )
                except InferenceError:
                    is_every_value_a_set = False

                if not is_every_value_a_set:
                    self.add_message(JOINALL_ID, node=node)
