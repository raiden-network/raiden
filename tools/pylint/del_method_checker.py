from astroid import FunctionDef
from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

from . import find_parent, ignore_tests

ID_DEL_METHOD = "del-method-used"
ID_EXCEPTION_IN_DEL = "exception-in-del"
MSG_DEL_METHOD = "Avoid using __del__ methods."
MSG_EXCEPTION_IN_DEL = "Don't raise Exceptions in __del__ methods."


def register(linter):
    linter.register_checker(DelMethod(linter))


class DelMethod(BaseChecker):
    __implements__ = IAstroidChecker

    name = "del-method"
    priority = -1
    msgs = {
        "C6493": (
            MSG_DEL_METHOD,
            ID_DEL_METHOD,
            (
                "__del__ methods are unreliable and should be avoided. "
                "Consider using a context manager instead."
            ),
        ),
        "E6494": (
            MSG_EXCEPTION_IN_DEL,
            ID_EXCEPTION_IN_DEL,
            (
                "Exceptions raised in __del__ methods are not propagated. See the warning "
                "at the end of https://docs.python.org/3.7/reference/datamodel.html#object.__del__"
            ),
        ),
    }

    @ignore_tests
    def visit_functiondef(self, node):
        if node.name == "__del__" and node.is_method():
            self.add_message(ID_DEL_METHOD, node=node)

    @ignore_tests
    def visit_raise(self, node):
        function_node = find_parent(node, FunctionDef)
        if function_node is not None:
            if function_node.name == "__del__" and function_node.is_method():
                self.add_message(ID_EXCEPTION_IN_DEL, node=node)
