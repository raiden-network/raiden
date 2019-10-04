def patch_all(
    socket: bool = True,
    dns: bool = True,
    time: bool = True,
    select: bool = True,
    thread: bool = True,
    os: bool = True,
    ssl: bool = True,
    httplib: bool = False,  # Deprecated, to be removed.
    subprocess: bool = True,
    sys: bool = False,
    aggressive: bool = True,
    Event: bool = True,
    builtins: bool = True,
    signal: bool = True,
    queue: bool = True,
    **kwargs,
): ...
