import opentracing
from requests_opentracing import SessionTracing

from raiden.network.transport.matrix.client import GMatrixClient


def matrix_client_enable_requests_tracing(client: GMatrixClient) -> None:
    """
    Enables requests tracing the the passed client.
    This is done by replacing the ``GMatrixClient.GMatrixHttpApi.session`` attribute with a
    ``SessionTracing`` replacement.
    """

    new_session = SessionTracing(propagate=False, span_tags={"target": "matrix"})

    new_session.adapters = client.api.session.adapters
    new_session.hooks = client.api.session.hooks

    client.api.session = new_session


def enable_pfs_request_tracing() -> None:
    """Enable tracing for pathfinding requests

    This is done by replacing the `Session` object in `raiden.network.pathfinding`.
    """

    from raiden.network import pathfinding

    # Propagate traces to the PFS
    tracing_session = SessionTracing(opentracing.tracer, propagate=True)
    tracing_session.headers = pathfinding.session.headers
    tracing_session.adapters = pathfinding.session.adapters

    pathfinding.session = tracing_session
