import logging
import sys
from operator import itemgetter

import gevent
import structlog
import urwid as uwd
from structlog.stdlib import ProcessorFormatter
from urwid import SimpleFocusListWalker

from scenario_player.runner import ScenarioRunner

PALETTE = [
    ('log_ts', 'light gray', 'default'),
    ('log_lvl_not_set', 'default', 'dark red'),
    ('log_lvl_debug', 'dark cyan', 'default'),
    ('log_lvl_info', 'dark green', 'default'),
    ('log_lvl_warning', 'yellow', 'default'),
    ('log_lvl_error', 'dark red', 'default'),
    ('log_lvl_exception', 'dark red', 'default'),
    ('log_lvl_critical', 'white', 'dark red'),
    ('log_event', 'white', 'default'),
    ('log_logger', 'light blue', 'default'),
    ('log_key', 'dark cyan', 'default'),
    ('log_value', 'dark magenta', 'default'),
    ('log_focus', '', 'dark blue'),
    ('focus', 'light blue', 'default'),
    ('status', 'white', 'dark blue'),
    ('task_state_initialized', 'white', 'default'),
    ('task_state_running', 'yellow', 'default'),
    ('task_state_finished', 'dark green', 'default'),
    ('task_state_errored', 'dark red', 'default'),
    ('task_duration', 'dark magenta', 'default'),
    ('task_name', 'dark blue', 'default'),
]
log = structlog.get_logger(__name__)


EVENT_LEN = 30

LOGGING_PROCESSORS = [
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.stdlib.PositionalArgumentsFormatter(),
    structlog.processors.TimeStamper(fmt="%Y-%m-%d %H:%M:%S"),
    structlog.processors.StackInfoRenderer(),
    structlog.processors.format_exc_info,
]


class _DummyFormatter(logging.Formatter):
    def format(self, record):
        return record


class NonStringifyingProcessorFormatter(ProcessorFormatter, _DummyFormatter):
    pass


class SelectableText(uwd.Text):
    _selectable = True

    def keypress(self, size, key):
        return key


class UrwidLogWalker(SimpleFocusListWalker):
    def write(self, content):
        if content is not None:
            self.extend([
                uwd.AttrMap(
                    SelectableText(line, wrap='clip'),
                    None,
                    focus_map='log_focus',
                )
                for line in content.msg
            ])

    def _adjust_focus_on_contents_modified(self, slc: slice, new_items=()):
        own_len = len(self)
        is_append = (
            slc.start == slc.stop == self._focus + 1 == own_len and
            slc.step is None and
            len(new_items)
        )
        if is_append:
            # Append to end and we're at the end - follow
            return own_len + len(new_items) - 1
        return super()._adjust_focus_on_contents_modified(slc, new_items)

    @property
    def at_end(self):
        return self._focus == len(self) - 1


class UrwidLogRenderer:
    def __call__(self, _, __, event_dict):
        log_line = []
        ts = event_dict.pop("timestamp", None)
        if ts is not None:
            log_line.append([
                ('log_ts', str(ts)),
                ' ',
            ])
        level = event_dict.pop("level", None)
        if level is not None:
            log_line.append([
                ('default', '['),
                (f'log_lvl_{level}', f'{level:9.9s}'),
                ('default', '] '),
            ])

        event = self._repr(event_dict.pop("event"))
        if event_dict:
            event = f'{event:{EVENT_LEN}s}'
        log_line.append([('log_event', event), ' '])

        logger_name = event_dict.pop("logger", None)
        if logger_name is not None:
            log_line.append([
                ('default', '['),
                ('log_logger', logger_name),
                ('default', '] '),
            ])

        stack = event_dict.pop("stack", None)
        exc = event_dict.pop("exception", None)

        log_line.extend(
            [('log_key', key), '=', ('log_value', self._repr(value)), ' ']
            for key, value in sorted(event_dict.items(), key=itemgetter(0))
        )
        log_lines = [log_line]

        if stack is not None:
            log_lines.extend(stack.splitlines())
            if exc is not None:
                log_lines.extend(['', '', '=' * 70, ''])
        if exc is not None:
            log_lines.extend(exc.splitlines())

        return log_lines

    def _repr(self, inst):
        if isinstance(inst, str):
            return inst.replace('\n', '\\n')
        else:
            return repr(inst)


class TaskTreeNode(uwd.ParentNode):
    def load_child_keys(self):
        return [t.id for t in getattr(self.get_value(), '_tasks', [])]

    def load_child_node(self, key):
        task = self.get_value()._runner.task_cache[key]
        return TaskTreeNode(task, self, task.id)

    def load_widget(self):
        return TaskWidget(self)


class TaskWidget(uwd.TreeWidget):
    def __init__(self, node):
        super().__init__(node)
        gevent.spawn(self._update_display_text)

    def get_display_text(self):
        return self._node.get_value().urwid_label

    def _update_display_text(self):
        while True:
            if self._innerwidget:
                self._innerwidget.set_text(self.get_display_text())
                if self._node.get_value().done:
                    # Stop updating once the task has entered a final state
                    return
            gevent.sleep(0.25)


class TabFocusSwitchingPile(uwd.Pile):
    def keypress(self, size, key):
        if not self.contents:
            return key

        if key == 'tab':
            self.focus_position = (self.focus_position + 1) % len(self.contents)
            return

        key = self.focus.keypress(size, key)
        if key:
            return key


class ScenarioUI:
    def __init__(self, runner: ScenarioRunner, log_walker, log_file_name):
        if not sys.stdout.isatty():
            return
        self._runner = runner
        self._log_walker = log_walker
        self._log_file_name = log_file_name

        self._task_box = uwd.LineBox(self._task_widget, title='Tasks', title_align='left')
        self._log_box = uwd.LineBox(self._log_widget, title='Log', title_align='left')
        uwd.connect_signal(self._log_walker, 'modified', self._update_log_box_title)
        self._header_text = uwd.Text('')
        self._status_text = uwd.Text('')
        self._update_header_text()
        self._update_status_text()
        self._root_widget = uwd.Frame(
            TabFocusSwitchingPile(
                [
                    uwd.AttrWrap(self._task_box, 'default', focus_attr='focus'),
                    uwd.AttrWrap(self._log_box, 'default', focus_attr='focus'),
                ],
                focus_item=1,
            ),
            header=uwd.AttrWrap(self._header_text, 'status'),
            footer=uwd.AttrWrap(self._status_text, 'status'),
        )
        self._loop = uwd.MainLoop(
            self._root_widget,
            handle_mouse=False,
            unhandled_input=self._handle_input,
            palette=PALETTE,
        )

    def run(self) -> gevent.Greenlet:
        if not sys.stdout.isatty():
            return gevent.spawn(lambda: True)

        def _wakeup():
            # Force loop wakeup every 250 milliseconds to update screen
            self._loop.event_loop.alarm(.25, _wakeup)

        _wakeup()
        return gevent.spawn(self._loop.run)

    @property
    def _task_widget(self):
        tree = TaskTreeNode(self._runner.root_task, key=self._runner.root_task.id)
        return uwd.TreeListBox(uwd.TreeWalker(tree))

    @property
    def _log_widget(self):
        return uwd.ListBox(self._log_walker)

    def _update_header_text(self):
        if self._runner.is_managed:
            node_count = len(self._runner.node_controller)
        else:
            node_count = len(self._runner.raiden_nodes)
        self._header_text.set_text(
            f'Scenario Player - '
            f'Nodes: {node_count} - '
            f'Tasks/Active: {self._runner.task_count}/{self._runner.running_task_count} - '
            f'Logfile: {self._log_file_name}',
        )

    def _update_status_text(self):
        self._status_text.set_text(
            'Keys: q: quit - '
            'Tab: Switch panes - '
            'f: Follow log - '
            '↑/↓/pg up/pg dwn: Scroll active pane - '
            '-/+: Collapse / expand task',
        )

    def _handle_input(self, key):
        if key == 'q':
            raise uwd.ExitMainLoop()
        elif key == 'f':
            self._log_walker.set_focus(len(self._log_walker) - 1)
        elif key in {'up', 'down', 'page up', 'page down'}:
            self._root_widget.body.focus.original_widget.original_widget.keypress(
                self._loop.screen_size,
                key,
            )
        else:
            log.info('key', key=key)

    def _update_log_box_title(self):
        if self._log_walker.at_end:
            focus = ', following'
        else:
            focus = f' @ {self._log_walker.focus}'
        self._log_box.set_title(f'Log - {len(self._log_walker)} lines{focus}')

    def set_success(self, success):
        if success:
            self._loop.screen.register_palette_entry('focus', 'dark green', 'default')
        else:
            self._loop.screen.register_palette_entry('focus', 'dark red', 'default')
