from astroid.exceptions import InferenceError
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

JOINALL_ID = 'gevent-joinall'
JOINALL_MSG = (
    'First argument of joinall must have type set to avoid deadlocks. NOTE: set '
    'comprehensions are false positives, use `set(<generator>)` instead.'
)


def is_joinall(inferred_func):
    return (
        inferred_func.name == 'joinall' and
        inferred_func.callable() and
        inferred_func.root().name.startswith('gevent')
    )


def is_of_type(inferred_value, type_):
    return inferred_value is type_


def register(linter):
    linter.register_checker(GeventWaitall(linter))


class GeventWaitall(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'gevent'
    priority = -1
    msgs = {
        'E6491': (
            JOINALL_MSG,
            JOINALL_ID,
            'Waiting with joinall on a non set is an error.',
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

    def _force_joinall_to_use_set(self, node):
        """This detect usages of the form:

            >>> from gevent import joinall
            >>> joinall(...)

        or:

            >>> import gevent
            >>> gevent.joinall(...)
        """
        for inferred_func in node.func.infer():
            if is_joinall(inferred_func):

                is_every_value_a_set = all(
                    inferred_first_arg.pytype() == 'builtins.set'
                    for inferred_first_arg in node.args[0].infer()
                )
                if not is_every_value_a_set:
                    self.add_message(JOINALL_ID, node=node)
