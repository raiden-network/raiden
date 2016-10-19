""" Stack and trace extraction utilities """
# This code is heavilly based on the raven-python from the Sentry Team.
#
# :copyright: (c) 2010-2012 by the Sentry Team, see AUTHORS for more details.
# :license: BSD, see LICENSE for more details.
import sys
import linecache


if sys.version_info[0] == 2:
    def iteritems(d, **kw):
        iterator = iter(d.items)
        return iterator(**kw)
else:
    def iteritems(d, **kw):
        iterator = iter(d.iteritems)
        return iterator(**kw)


def _getitem_from_frame(f_locals, key, default=None):
    """
    f_locals is not guaranteed to have .get(), but it will always
    support __getitem__. Even if it doesn't, we return ``default``.
    """
    try:
        return f_locals[key]
    except Exception:
        return default


def to_dict(dictish):
    """
    Given something that closely resembles a dictionary, we attempt
    to coerce it into a propery dictionary.
    """
    if hasattr(dictish, 'iterkeys'):
        method = dictish.iterkeys
    elif hasattr(dictish, 'keys'):
        method = dictish.keys
    else:
        raise ValueError(dictish)

    return dict((k, dictish[k]) for k in method())


def get_lines_from_file(filename, lineno, context_lines, loader=None, module_name=None):
    """
    Returns context_lines before and after lineno from file.
    Returns (pre_context_lineno, pre_context, context_line, post_context).
    """

    source = None
    if loader is not None and hasattr(loader, "get_source"):
        try:
            source = loader.get_source(module_name)
        except ImportError:
            source = None
        if source is not None:
            source = source.splitlines()

    if source is None:
        try:
            source = linecache.getlines(filename)
        except (OSError, IOError):
            return None, None, None

    if not source:
        return None, None, None

    lower_bound = max(0, lineno - context_lines)
    upper_bound = min(lineno + 1 + context_lines, len(source))

    try:
        pre_context = [line.strip('\r\n') for line in source[lower_bound:lineno]]
        context_line = source[lineno].strip('\r\n')
        post_context = [line.strip('\r\n') for line in
                        source[(lineno + 1):upper_bound]]
    except IndexError:
        # the file may have changed since it was loaded into memory
        return None, None, None

    return pre_context, context_line, post_context


def get_frame_locals(frame):
    f_locals = getattr(frame, 'f_locals', None)
    if not f_locals:
        return None

    if not isinstance(f_locals, dict):
        try:
            f_locals = to_dict(f_locals)
        except Exception:
            return None

    f_vars = {}
    f_size = 0
    for key, value in iteritems(f_locals):
        v_size = len(repr(value))
        if v_size + f_size < 4096:
            f_vars[key] = value
            f_size += v_size
    return f_vars


def get_stack_info(frame):
    frame_result = get_trace_info(frame)

    abs_path = frame_result.get('abs_path')
    lineno = frame_result['lineno']
    module_name = frame_result['module']

    f_globals = getattr(frame, 'f_globals', {})
    loader = _getitem_from_frame(f_globals, '__loader__')

    if lineno is not None and abs_path:
        line_data = get_lines_from_file(abs_path, lineno - 1, 5, loader, module_name)
        pre_context, context_line, post_context = line_data

        frame_result.update({
            'pre_context': pre_context,
            'context_line': context_line,
            'post_context': post_context,
        })

    f_vars = get_frame_locals(frame)
    if f_vars:
        frame_result['vars'] = f_vars

    return frame_result


def get_trace_info(frame):
    if isinstance(frame, (list, tuple)):
        frame, lineno = frame
    else:
        frame = frame
        lineno = frame.f_lineno

    f_globals = getattr(frame, 'f_globals', {})
    f_code = getattr(frame, 'f_code', None)

    module_name = _getitem_from_frame(f_globals, '__name__')

    if f_code:
        abs_path = frame.f_code.co_filename
        function = frame.f_code.co_name
    else:
        abs_path = None
        function = None

    # Try to pull a relative file path
    # This changes /foo/site-packages/baz/bar.py into baz/bar.py
    try:
        base_filename = sys.modules[module_name.split('.', 1)[0]].__file__
        filename = abs_path.split(base_filename.rsplit('/', 2)[0], 1)[-1].lstrip("/")
    except:
        filename = abs_path

    if not filename:
        filename = abs_path

    return {
        'runtime_id': id(f_code),
        'abs_path': abs_path,
        'filename': filename,
        'module': module_name or None,
        'function': function or '<unknown>',
        'lineno': lineno,
    }


def get_stack_from_frame(frame):
    result = []

    while frame:
        frame_result = get_stack_info(frame)
        result.append(frame_result)
        frame = frame.f_back

    return result[::-1]


def get_trace_from_frame(frame):
    result = []

    while frame:
        stack_result = get_trace_info(frame)
        result.append(stack_result)
        frame = frame.f_back

    # we iterate from the inner to the outter frame, so reverse it
    return result[::-1]
