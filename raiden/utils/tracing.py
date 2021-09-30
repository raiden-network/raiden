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
