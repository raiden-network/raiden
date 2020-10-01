import pickle
from typing import TypeVar

T = TypeVar("T")


def deepcopy(data: T) -> T:
    """Profiling `deepcopy.deepcopy` show that this function is very slow for
    largish objects (around 1MB of data). Since most of our objects don't use
    nested classes, this can be circumvented by using pickle to serialize and
    deserialize a new copy of the objects.
    """
    return pickle.loads(pickle.dumps(data, pickle.HIGHEST_PROTOCOL))
