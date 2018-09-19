from pylint.checkers import BaseChecker
from pylint.interfaces import IAstroidChecker

C0001_help = (
    'All spawned greenlets must be waited for, '
    'to ensure that exceptions are properly handled'
)


class SupervisedGreenlets(BaseChecker):
    __implements__ = IAstroidChecker

    name = 'supervised-greenlets'
    priority = -1
    msgs = {
        'C0001': (
            'Greenlet is not being waited for.',
            'supervised-greenlets-missing-wait',
            C0001_help,
        ),
    }

    def __init__(self, linter=None):
        super().__init__(linter)

    def visit_call(self, node):
        function_types = (
            astroid.FunctionDef,
            astroid.UnboundMethod,
            astroid.BoundMethod,
        )

        for call in node.infer():
            if isinstance(call, function_types):


def register(linter):
    linter.register_checker(SupervisedGreenlets(linter))
