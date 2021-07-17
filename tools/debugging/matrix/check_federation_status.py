import hashlib

import random
import string
from collections import defaultdict
from dataclasses import dataclass
from itertools import permutations
from typing import Dict, List, Optional, Tuple

import click
from matrix_client.errors import MatrixRequestError
from structlog import get_logger

from raiden.constants import DeviceIDs, ServerListType
from raiden.exceptions import TransportError
from raiden.network.transport.matrix import login, make_client
from raiden.network.transport.matrix.client import GMatrixClient, MatrixMessage
from raiden.utils.cli import get_matrix_servers
from raiden.utils.signer import LocalSigner

log = get_logger(__name__)


@dataclass
class FederationError:
    source_server: str
    target_sever: Optional[str]
    reason: str


class FederationChecker:
    def __init__(self, known_servers_list_url: str) -> None:
        self._known_servers_list_url = known_servers_list_url
        self._seed: str = "".join(random.choice(string.ascii_letters) for _ in range(10))
        self._clients: Dict[str, GMatrixClient] = {}
        self._errors: Dict[str, List[Tuple[str, Exception]]] = defaultdict(list)

    def check(self) -> List[FederationError]:
        clients, errors = self._make_clients()
        errors.extend(self._run_check(clients))
        return errors

    def _make_clients(self) -> Tuple[Dict[str, GMatrixClient], List[FederationError]]:
        def _dummy_callback(_: List[MatrixMessage]) -> bool:
            return True

        errors: List[FederationError] = []
        clients: Dict[str, GMatrixClient] = {}

        known_servers = get_matrix_servers(
            self._known_servers_list_url, ServerListType.ALL_SERVERS
        )

        for current_server in known_servers:
            signer = LocalSigner(
                hashlib.sha256(f"pk-{self._seed}-{current_server}".encode()).digest()
            )
            try:
                clients[current_server] = client = make_client(_dummy_callback, [current_server])
                login(client=client, signer=signer, device_id=DeviceIDs.RAIDEN)
            except (TransportError, MatrixRequestError) as ex:
                error = FederationError(
                    source_server=current_server,
                    target_sever=None,
                    reason=f"Could not connect to {current_server}: {ex}",
                )
                log.error("Error connecting", error=error)
                errors.append(error)
        return clients, errors

    @staticmethod
    def _run_check(clients: Dict[str, GMatrixClient]) -> List[FederationError]:
        results: List[FederationError] = []
        for (source_server, source_client), (target_sever, target_client) in permutations(
            clients.items(), 2
        ):
            log.info("Checking", source_server=source_server, target_sever=target_sever)
            try:
                source_client.get_user(target_client.user_id).get_display_name()
            except Exception as ex:
                error = FederationError(
                    source_server=source_server,
                    target_sever=target_sever,
                    reason=f"Couldn't fetch profile: {ex}",
                )
                log.error("Error fetching profile", error=error, exception=str(ex))
                results.append(error)
        return results


@click.command()
@click.option("-l", "--known-servers-list-url", required=True)
@click.option("--seed", required=True, help="Seed for private key")
def main(known_servers_list_url: str, seed: str) -> None:
    random.seed(seed)
    errors = FederationChecker(known_servers_list_url).check()
    if errors:
        user_errors = set()
        s = click.style
        for error in errors:
            if error.target_sever is None:
                user_errors.add(f"{s(error.source_server, fg='red')}:\n" f"    {error.reason}")
            else:
                user_errors.add(
                    f"{s(error.source_server, fg='yellow')} -> "
                    f"{s(error.target_sever, fg='yellow')}:\n"
                    f"    {error.reason}"
                )
        click.secho("Federation has issues:", fg="red")
        click.echo("\n".join(user_errors))
    else:
        click.secho("Federation appears healthy", fg="green")


if __name__ == "__main__":
    main()  # pylint: disable=no-value-for-parameter
