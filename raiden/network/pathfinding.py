import json
import random
import sys
from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, unique
from uuid import UUID

import click
import requests
import structlog
from eth_utils import (
    decode_hex,
    encode_hex,
    is_same_address,
    to_canonical_address,
    to_checksum_address,
    to_hex,
)
from web3 import Web3

from raiden.constants import DEFAULT_HTTP_REQUEST_TIMEOUT, ZERO_TOKENS, RoutingMode
from raiden.exceptions import ServiceRequestFailed, ServiceRequestIOURejected
from raiden.network.proxies.service_registry import ServiceRegistry
from raiden.network.utils import get_response_json
from raiden.utils.signer import LocalSigner
from raiden.utils.typing import (
    Address,
    Any,
    BlockNumber,
    BlockSpecification,
    ChainID,
    Dict,
    InitiatorAddress,
    List,
    Optional,
    PaymentAmount,
    Signature,
    TargetAddress,
    TokenAmount,
    TokenNetworkAddress,
    Tuple,
)
from raiden_contracts.utils.proofs import sign_one_to_n_iou

log = structlog.get_logger(__name__)


@dataclass(frozen=True)
class PFSInfo:
    url: str
    price: TokenAmount
    chain_id: ChainID
    token_network_registry_address: TokenNetworkAddress
    payment_address: Address
    message: str
    operator: str
    version: str


@dataclass
class PFSConfig:
    info: PFSInfo
    maximum_fee: TokenAmount
    iou_timeout: BlockNumber
    max_paths: int


@dataclass
class IOU:
    sender: Address
    receiver: Address
    one_to_n_address: Address
    amount: TokenAmount
    expiration_block: BlockNumber
    chain_id: ChainID
    signature: Optional[Signature] = None

    def sign(self, privkey: bytes) -> None:
        self.signature = Signature(
            sign_one_to_n_iou(
                privatekey=encode_hex(privkey),
                sender=to_checksum_address(self.sender),
                receiver=to_checksum_address(self.receiver),
                amount=self.amount,
                expiration_block=self.expiration_block,
                one_to_n_address=to_checksum_address(self.one_to_n_address),
                chain_id=self.chain_id,
            )
        )

    def as_json(self) -> Dict[str, Any]:
        data = dict(
            sender=to_checksum_address(self.sender),
            receiver=to_checksum_address(self.receiver),
            one_to_n_address=to_checksum_address(self.one_to_n_address),
            amount=self.amount,
            expiration_block=self.expiration_block,
            chain_id=self.chain_id,
        )

        if self.signature is not None:
            data["signature"] = to_hex(self.signature)

        return data


@unique
class PFSError(IntEnum):
    """ Error codes as returned by the PFS.

    Defined in the pathfinding_service.exceptions module in
    https://github.com/raiden-network/raiden-services
    """

    # TODO: link to PFS spec as soon as the error codes are added there.

    INVALID_REQUEST = 2000
    INVALID_SIGNATURE = 2001
    REQUEST_OUTDATED = 2002

    BAD_IOU = 2100
    MISSING_IOU = 2101
    WRONG_IOU_RECIPIENT = 2102
    IOU_EXPIRED_TOO_EARLY = 2103
    INSUFFICIENT_SERVICE_PAYMENT = 2104
    IOU_ALREADY_CLAIMED = 2105
    USE_THIS_IOU = 2106
    DEPOSIT_TOO_LOW = 2107

    @staticmethod
    def is_iou_rejected(error_code):
        return error_code >= 2100


MAX_PATHS_QUERY_ATTEMPTS = 2


def get_pfs_info(url: str) -> Optional[PFSInfo]:
    try:
        response = requests.get(f"{url}/api/v1/info", timeout=DEFAULT_HTTP_REQUEST_TIMEOUT)
        infos = get_response_json(response)

        return PFSInfo(
            url=url,
            price=infos["price_info"],
            chain_id=infos["network_info"]["chain_id"],
            token_network_registry_address=to_canonical_address(
                infos["network_info"]["registry_address"]
            ),
            payment_address=to_canonical_address(infos["payment_address"]),
            message=infos["message"],
            operator=infos["operator"],
            version=infos["version"],
        )
    except (json.JSONDecodeError, requests.exceptions.RequestException, KeyError):
        return None


def get_random_pfs(
    service_registry: ServiceRegistry, block_identifier: BlockSpecification
) -> Optional[str]:
    """Selects a random PFS from service_registry.

    Returns a tuple of the chosen services url and eth address.
    If there are no PFS in the given registry, it returns (None, None).
    """
    number_of_addresses = service_registry.ever_made_deposits_len(
        block_identifier=block_identifier
    )
    indices_to_try = list(range(number_of_addresses))
    random.shuffle(indices_to_try)

    address = None
    while indices_to_try:
        index = indices_to_try.pop()
        address = service_registry.ever_made_deposits(
            block_identifier=block_identifier, index=index
        )
        if not address:
            continue
        is_valid = service_registry.has_valid_registration(
            address=address, block_identifier=block_identifier
        )
        if not is_valid:
            continue

    if address is None:
        return None
    url = service_registry.get_service_url(
        block_identifier=block_identifier, service_hex_address=to_canonical_address(address)
    )
    return url


def configure_pfs_or_exit(
    pfs_url: str,
    routing_mode: RoutingMode,
    service_registry: Optional[ServiceRegistry],
    node_network_id: ChainID,
    token_network_registry_address: Address,
) -> PFSInfo:
    """
    Take in the given pfs_address argument, the service registry and find out a
    pfs address to use.

    If pfs_url is provided we use that.
    If pfs_url is 'auto' then we randomly choose a PFS address from the registry
    """
    msg = "Invalid code path; configure pfs needs routing mode PFS"
    assert routing_mode == RoutingMode.PFS, msg

    msg = "With PFS routing mode we shouldn't get to configure pfs with pfs_address being None"
    assert pfs_url, msg
    if pfs_url == "auto":
        assert service_registry, "Should not get here without a service registry"
        block_hash = service_registry.client.get_confirmed_blockhash()
        maybe_pfs_url = get_random_pfs(
            service_registry=service_registry, block_identifier=block_hash
        )
        if maybe_pfs_url is None:
            click.secho(
                "The service registry has no registered path finding service "
                "and we don't use basic routing."
            )
            sys.exit(1)
        else:
            pfs_url = maybe_pfs_url

    pathfinding_service_info = get_pfs_info(pfs_url)
    if not pathfinding_service_info:
        click.secho(
            f"There is an error with the pathfinding service with address "
            f"{pfs_url}. Raiden will shut down."
        )
        sys.exit(1)

    if pathfinding_service_info.price > 0 and not pathfinding_service_info.payment_address:
        click.secho(
            f"The pathfinding service at {pfs_url} did not provide an eth address "
            f"to pay it. Raiden will shut down. Please try a different PFS."
        )
        sys.exit(1)

    if not node_network_id == pathfinding_service_info.chain_id:
        click.secho(f"Invalid reply from pathfinding service {pfs_url}", fg="red")
        click.secho(
            f"PFS is not operating on the same network "
            f"({pathfinding_service_info.chain_id}) as your node is ({node_network_id}).\n"
            f"Raiden will shut down. Please choose a different PFS."
        )
        sys.exit(1)

    if not is_same_address(
        pathfinding_service_info.token_network_registry_address, token_network_registry_address
    ):
        click.secho(f"Invalid reply from pathfinding service {pfs_url}", fg="red")
        click.secho(
            f"PFS is not operating on the same Token Network Registry "
            f"({to_checksum_address(pathfinding_service_info.token_network_registry_address)})"
            f" as your node is ({to_checksum_address(token_network_registry_address)}).\n"
            f"Raiden will shut down. Please choose a different PFS."
        )
        sys.exit(1)

    click.secho(
        f"You have chosen the pathfinding service at {pfs_url}.\n"
        f"Operator: {pathfinding_service_info.operator}, "
        f"running version: {pathfinding_service_info.version}, "
        f"chain_id: {pathfinding_service_info.chain_id}.\n"
        f"Fees will be paid to {to_checksum_address(pathfinding_service_info.payment_address)}. "
        f"For each request costs {pathfinding_service_info.price}.\n"
        f"Message from the PFS:\n{pathfinding_service_info.message}"
    )

    log.info("Using PFS", pfs_info=pathfinding_service_info)

    return pathfinding_service_info


def get_last_iou(
    url: str,
    token_network_address: TokenNetworkAddress,
    sender: Address,
    receiver: Address,
    privkey: bytes,
) -> Optional[IOU]:

    timestamp = datetime.utcnow().isoformat(timespec="seconds")
    signature_data = sender + receiver + Web3.toBytes(text=timestamp)
    signature = to_hex(LocalSigner(privkey).sign(signature_data))

    try:
        response = requests.get(
            f"{url}/api/v1/{to_checksum_address(token_network_address)}/payment/iou",
            params=dict(
                sender=to_checksum_address(sender),
                receiver=to_checksum_address(receiver),
                timestamp=timestamp,
                signature=signature,
            ),
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        )

        data = json.loads(response.content).get("last_iou")

        if data is None:
            return None

        return IOU(
            sender=to_canonical_address(data["sender"]),
            receiver=to_canonical_address(data["receiver"]),
            one_to_n_address=to_canonical_address(data["one_to_n_address"]),
            amount=data["amount"],
            expiration_block=data["expiration_block"],
            chain_id=data["chain_id"],
            signature=Signature(decode_hex(data["signature"])),
        )
    except (requests.exceptions.RequestException, ValueError, KeyError) as e:
        raise ServiceRequestFailed(str(e))


def make_iou(
    pfs_config: PFSConfig,
    our_address: Address,
    one_to_n_address: Address,
    privkey: bytes,
    block_number: BlockNumber,
    chain_id: ChainID,
    offered_fee: TokenAmount,
) -> IOU:
    expiration = BlockNumber(block_number + pfs_config.iou_timeout)

    iou = IOU(
        sender=our_address,
        receiver=pfs_config.info.payment_address,
        one_to_n_address=one_to_n_address,
        amount=offered_fee,
        expiration_block=expiration,
        chain_id=chain_id,
    )
    iou.sign(privkey)

    return iou


def update_iou(
    iou: IOU,
    privkey: bytes,
    added_amount: TokenAmount = ZERO_TOKENS,
    expiration_block: Optional[BlockNumber] = None,
) -> IOU:

    expected_signature = Signature(
        sign_one_to_n_iou(
            privatekey=to_hex(privkey),
            sender=to_checksum_address(iou.sender),
            receiver=to_checksum_address(iou.receiver),
            amount=iou.amount,
            expiration_block=iou.expiration_block,
            one_to_n_address=to_checksum_address(iou.one_to_n_address),
            chain_id=iou.chain_id,
        )
    )
    if iou.signature != expected_signature:
        raise ServiceRequestFailed(
            "Last IOU as given by the pathfinding service is invalid (signature does not match)"
        )

    iou.amount = TokenAmount(iou.amount + added_amount)
    if expiration_block:
        iou.expiration_block = expiration_block

    iou.sign(privkey)

    return iou


def create_current_iou(
    pfs_config: PFSConfig,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: Address,
    our_address: Address,
    privkey: bytes,
    block_number: BlockNumber,
    chain_id: ChainID,
    offered_fee: TokenAmount,
    scrap_existing_iou: bool = False,
) -> IOU:

    latest_iou = None
    if not scrap_existing_iou:
        latest_iou = get_last_iou(
            url=pfs_config.info.url,
            token_network_address=token_network_address,
            sender=our_address,
            receiver=pfs_config.info.payment_address,
            privkey=privkey,
        )

    if latest_iou is None:
        return make_iou(
            pfs_config=pfs_config,
            our_address=our_address,
            privkey=privkey,
            block_number=block_number,
            chain_id=chain_id,
            offered_fee=offered_fee,
            one_to_n_address=one_to_n_address,
        )
    else:
        added_amount = offered_fee
        return update_iou(iou=latest_iou, privkey=privkey, added_amount=added_amount)


def post_pfs_paths(
    url: str, token_network_address: TokenNetworkAddress, payload: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], UUID]:
    try:
        response = requests.post(
            f"{url}/api/v1/{to_checksum_address(token_network_address)}/paths",
            json=payload,
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        raise ServiceRequestFailed(
            f"Could not connect to Pathfinding Service ({str(e)})",
            dict(parameters=payload, exc_info=True),
        )

    if response.status_code != 200:
        info = {"http_error": response.status_code}
        try:
            response_json = get_response_json(response)
        except ValueError:
            raise ServiceRequestFailed(
                "Pathfinding service returned error code (malformed json in response)", info
            )
        else:
            error = info["error"] = response_json.get("errors")
            error_code = info["error_code"] = response_json.get("error_code", 0)
            if PFSError.is_iou_rejected(error_code):
                raise ServiceRequestIOURejected(error, error_code)

        raise ServiceRequestFailed("Pathfinding service returned error code", info)

    try:
        response_json = get_response_json(response)
        return response_json["result"], UUID(response_json["feedback_token"])
    except KeyError:
        raise ServiceRequestFailed(
            "Answer from pathfinding service not understood ('result' field missing)",
            dict(response=get_response_json(response)),
        )
    except ValueError:
        raise ServiceRequestFailed(
            "Pathfinding service returned invalid json",
            dict(response_text=response.text, exc_info=True),
        )


def query_paths(
    pfs_config: PFSConfig,
    our_address: Address,
    privkey: bytes,
    current_block_number: BlockNumber,
    token_network_address: TokenNetworkAddress,
    one_to_n_address: Address,
    chain_id: ChainID,
    route_from: InitiatorAddress,
    route_to: TargetAddress,
    value: PaymentAmount,
) -> Tuple[List[Dict[str, Any]], Optional[UUID]]:
    """ Query paths from the PFS.

    Send a request to the /paths endpoint of the PFS specified in service_config, and
    retry in case of a failed request if it makes sense.
    """

    payload = {
        "from": to_checksum_address(route_from),
        "to": to_checksum_address(route_to),
        "value": value,
        "max_paths": pfs_config.max_paths,
    }
    offered_fee = pfs_config.info.price
    scrap_existing_iou = False

    for retries in reversed(range(MAX_PATHS_QUERY_ATTEMPTS)):
        if offered_fee > 0:
            new_iou = create_current_iou(
                pfs_config=pfs_config,
                token_network_address=token_network_address,
                one_to_n_address=one_to_n_address,
                our_address=our_address,
                privkey=privkey,
                chain_id=chain_id,
                block_number=current_block_number,
                offered_fee=offered_fee,
                scrap_existing_iou=scrap_existing_iou,
            )
            payload["iou"] = new_iou.as_json()

        log.info(
            "Requesting paths from Pathfinding Service",
            url=pfs_config.info.url,
            token_network_address=token_network_address,
            payload=payload,
        )

        try:
            return post_pfs_paths(
                url=pfs_config.info.url,
                token_network_address=token_network_address,
                payload=payload,
            )
        except ServiceRequestIOURejected as error:
            code = error.error_code
            if retries == 0 or code in (PFSError.WRONG_IOU_RECIPIENT, PFSError.DEPOSIT_TOO_LOW):
                raise
            elif code in (PFSError.IOU_ALREADY_CLAIMED, PFSError.IOU_EXPIRED_TOO_EARLY):
                scrap_existing_iou = True
            elif code == PFSError.INSUFFICIENT_SERVICE_PAYMENT:
                new_info = get_pfs_info(pfs_config.info.url)
                if new_info is None:
                    raise ServiceRequestFailed("Could not get updated fees from PFS.")
                if new_info.price > pfs_config.maximum_fee:
                    raise ServiceRequestFailed("PFS fees too high.")
                log.info(f"PFS increased fees", new_price=new_info.price)
                pfs_config.info = new_info
            log.info(f"PFS rejected our IOU, reason: {error}. Attempting again.")

    # If we got no results after MAX_PATHS_QUERY_ATTEMPTS return empty list of paths
    return list(), None


def post_pfs_feedback(
    routing_mode: RoutingMode,
    pfs_config: PFSConfig,
    token_network_address: TokenNetworkAddress,
    route: List[Address],
    token: UUID,
    succesful: bool,
) -> None:

    feedback_disabled = routing_mode == RoutingMode.PRIVATE or pfs_config is None
    if feedback_disabled:
        return

    hex_route = [to_checksum_address(address) for address in route]
    payload = dict(token=token.hex, path=hex_route, success=succesful)

    log.info(
        "Sending routing feedback to Pathfinding Service",
        url=pfs_config.info.url,
        token_network_address=token_network_address,
        payload=payload,
    )

    try:
        requests.post(
            f"{pfs_config.info.url}/api/v1/{to_checksum_address(token_network_address)}/feedback",
            json=payload,
            timeout=DEFAULT_HTTP_REQUEST_TIMEOUT,
        )
    except requests.RequestException as e:
        log.warning(
            f"Could not send feedback to Pathfinding Service", exception_=str(e), payload=payload
        )
