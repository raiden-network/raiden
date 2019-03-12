import pathlib

from typing import List, Dict, Union, Optional, Any


def render_options(
    options: Union[List[str], Dict[str, str]],
    short_hand: bool=False,
) -> None:
    """Render the given options to the console.

    If `short_hand` is True, we render a shorter description of options. Output
    depends on the type of `options`.

    If `options` is a list, we display it as a numbered list of its element::

        >>>ops = ['potato', 'tomato', 'sangria']
        ['potato', 'tomato', 'sangria']
        >>>render_options(ops)
        "Choose one of the following:"
        "    [1]    potato"
        "    [2]    tomato"
        "    [3]    sangria"

    Or, if a short hand is requested, we condense it to a single line:

        >>>render_options(ops, short_hand=True)
        "Choose one of [1, 2, 3]:"

    Should `options` be a dictionary, we use the keys instead::

        >>>ops = {'ok': 'potato', 'better': 'tomato', 'best': 'sangria'}
        ['potato', 'tomato', 'sangria']
        >>>render_options(ops)
        "Choose one of the following:"
        "    [ok]       potato"
        "    [better]   tomato"
        "    [best]     sangria"
        >>>render_options(ops, short_hand=True)
        "Choose one of [ok, better, best]:"

    TODO: This is a stub
    """


def user_input(
    prompt: str,
    default: Optional[str] = None,
    options: Optional[Union[Dict[str, str], List[str]]] = None,
) -> Any:
    """Ask the user for his input."""
    render_options(options)

    while True:
        response = input(prompt)
        if options is None:
            return response or default
        elif response in options:
            return response
        render_options(options, short_hand=True)


def create_symlink(bin_path: pathlib.Path) -> None:
    """Create a symlink at /usr/local/bin for the given `bin_path`.

    TODO: This is a stub.
    """


def create_desktop_icon(bin_path: pathlib.Path) -> None:
    """Create a desktop icon for the given `bin_path`.

    TODO: This is a stub.
    """


def download_file(target_path: pathlib.Path, url: str) -> pathlib.Path:
    """Download the file at given `url` to `target_path`.

    TODO: This is a stub.
    """


def is_testnet(network: str) -> bool:
    """Check if the given `network` is a test network.

    # TODO: This is a Stub.
    """
    return bool(network)

