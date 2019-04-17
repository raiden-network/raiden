from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

ASSERT_ID = 'assert-message'
ASSERT_MSG = (
    'Every assert must have a message describing the error to aid debugging'
)


def register(linter):
    linter.register_checker(AssertMessage(linter))


class AssertMessage(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'assert'
    priority = -1
    msgs = {
        'E6492': (ASSERT_MSG, ASSERT_ID, 'Assert without message.'),
    }

    def visit_assert(self, node):
        if len(list(node.get_children())) != 2:
            self.add_message(ASSERT_ID, node=node)
