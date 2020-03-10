from flask import Blueprint, Response
from flask_restful import Resource
from webargs.flaskparser import use_kwargs

from raiden.api.rest_utils import if_api_available
from raiden.api.v1.encoding import (
    BlockchainEventsRequestSchema,
    ChannelPatchSchema,
    ChannelPutSchema,
    ConnectionsConnectSchema,
    ConnectionsLeaveSchema,
    MintTokenSchema,
    PaymentSchema,
    RaidenEventsRequestSchema,
)
from raiden.constants import BLOCK_ID_LATEST
from raiden.utils.typing import (
    TYPE_CHECKING,
    Address,
    Any,
    BlockIdentifier,
    BlockTimeout,
    PaymentAmount,
    PaymentID,
    Secret,
    SecretHash,
    TargetAddress,
    TokenAddress,
    TokenAmount,
)

if TYPE_CHECKING:
    from raiden.api.rest import RestAPI


def create_blueprint() -> Blueprint:
    # Take a look at this SO question on hints how to organize versioned
    # API with flask:
    # http://stackoverflow.com/questions/28795561/support-multiple-api-versions-in-flask#28797512
    return Blueprint("v1_resources", __name__)


class BaseResource(Resource):
    def __init__(self, rest_api_object: "RestAPI", **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.rest_api = rest_api_object


class AddressResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_our_address()


class VersionResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_raiden_version()


class ChannelsResource(BaseResource):

    put_schema = ChannelPutSchema

    @if_api_available
    def get(self) -> Response:
        """
        this translates to 'get all channels the node is connected with'
        """
        return self.rest_api.get_channel_list(
            self.rest_api.raiden_api.raiden.default_registry.address
        )

    @use_kwargs(put_schema, locations=("json",))
    @if_api_available
    def put(self, **kwargs: Any) -> Response:
        return self.rest_api.open(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class ChannelsResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, **kwargs: Any) -> Response:
        """
        this translates to 'get all channels the node is connected to for the given token address'
        """
        return self.rest_api.get_channel_list(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class ChannelsResourceByTokenAndPartnerAddress(BaseResource):

    patch_schema = ChannelPatchSchema

    @use_kwargs(patch_schema, locations=("json",))
    @if_api_available
    def patch(self, **kwargs: Any) -> Response:
        return self.rest_api.patch_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )

    @if_api_available
    def get(self, **kwargs: Any) -> Response:
        return self.rest_api.get_channel(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address, **kwargs
        )


class TokensResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        """
        this translates to 'get all token addresses we have channels open for'
        """
        return self.rest_api.get_tokens_list(
            self.rest_api.raiden_api.raiden.default_registry.address
        )


class PartnersResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_partners_by_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )


class BlockchainEventsNetworkResource(BaseResource):

    get_schema = BlockchainEventsRequestSchema()

    @use_kwargs(get_schema, locations=("query",))
    @if_api_available
    def get(self, from_block: BlockIdentifier, to_block: BlockIdentifier) -> Response:
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or BLOCK_ID_LATEST

        return self.rest_api.get_blockchain_events_network(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            from_block=from_block,
            to_block=to_block,
        )


class BlockchainEventsTokenResource(BaseResource):

    get_schema = BlockchainEventsRequestSchema()

    @use_kwargs(get_schema, locations=("query",))
    @if_api_available
    def get(
        self, token_address: TokenAddress, from_block: BlockIdentifier, to_block: BlockIdentifier
    ) -> Response:
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or BLOCK_ID_LATEST

        return self.rest_api.get_blockchain_events_token_network(
            token_address=token_address, from_block=from_block, to_block=to_block
        )


class ChannelBlockchainEventsResource(BaseResource):

    get_schema = BlockchainEventsRequestSchema()

    @use_kwargs(get_schema, locations=("query",))
    @if_api_available
    def get(
        self,
        token_address: TokenAddress,
        partner_address: Address = None,
        from_block: BlockIdentifier = None,
        to_block: BlockIdentifier = None,
    ) -> Response:
        from_block = from_block or self.rest_api.raiden_api.raiden.query_start_block
        to_block = to_block or BLOCK_ID_LATEST

        return self.rest_api.get_blockchain_events_channel(
            token_address=token_address,
            partner_address=partner_address,
            from_block=from_block,
            to_block=to_block,
        )


class RaidenInternalEventsResource(BaseResource):

    get_schema = RaidenEventsRequestSchema()

    @use_kwargs(get_schema, locations=("query",))
    @if_api_available
    def get(self, limit: int = None, offset: int = None) -> Response:
        return self.rest_api.get_raiden_internal_events_with_timestamps(limit=limit, offset=offset)


class RegisterTokenResource(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_token_network_for_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )

    @if_api_available
    def put(self, token_address: TokenAddress) -> Response:
        return self.rest_api.register_token(
            self.rest_api.raiden_api.raiden.default_registry.address, token_address
        )


class MintTokenResource(BaseResource):
    post_schema = MintTokenSchema

    @use_kwargs(post_schema, locations=("json",))
    @if_api_available
    def post(self, token_address: TokenAddress, to: Address, value: TokenAmount) -> Response:
        return self.rest_api.mint_token_for(token_address=token_address, to=to, value=value)


class ConnectionsResource(BaseResource):

    put_schema = ConnectionsConnectSchema()
    delete_schema = ConnectionsLeaveSchema()

    @use_kwargs(put_schema)
    @if_api_available
    def put(
        self,
        token_address: TokenAddress,
        funds: TokenAmount,
        initial_channel_target: int,
        joinable_funds_target: float,
    ) -> Response:
        return self.rest_api.connect(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            funds=funds,
            initial_channel_target=initial_channel_target,
            joinable_funds_target=joinable_funds_target,
        )

    @use_kwargs(delete_schema, locations=("json",))
    @if_api_available
    def delete(self, token_address: TokenAddress) -> Response:
        return self.rest_api.leave(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
        )


class ConnectionsInfoResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_connection_managers_info(
            self.rest_api.raiden_api.raiden.default_registry.address
        )


class PaymentResource(BaseResource):

    post_schema = PaymentSchema(
        only=("amount", "identifier", "secret", "secret_hash", "lock_timeout")
    )
    get_schema = RaidenEventsRequestSchema()

    @use_kwargs(get_schema, locations=("query",))
    @if_api_available
    def get(
        self,
        token_address: TokenAddress = None,
        target_address: Address = None,
        limit: int = None,
        offset: int = None,
    ) -> Response:
        return self.rest_api.get_raiden_events_payment_history_with_timestamps(
            token_address=token_address, target_address=target_address, limit=limit, offset=offset
        )

    @use_kwargs(post_schema, locations=("json",))
    @if_api_available
    def post(
        self,
        token_address: TokenAddress,
        target_address: TargetAddress,
        amount: PaymentAmount,
        identifier: PaymentID,
        secret: Secret,
        secret_hash: SecretHash,
        lock_timeout: BlockTimeout,
    ) -> Response:
        return self.rest_api.initiate_payment(
            registry_address=self.rest_api.raiden_api.raiden.default_registry.address,
            token_address=token_address,
            target_address=target_address,
            amount=amount,
            identifier=identifier,
            secret=secret,
            secret_hash=secret_hash,
            lock_timeout=lock_timeout,
        )


class PendingTransfersResource(BaseResource):
    @if_api_available
    def get(self) -> Response:
        return self.rest_api.get_pending_transfers()


class PendingTransfersResourceByTokenAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress) -> Response:
        return self.rest_api.get_pending_transfers(token_address)


class PendingTransfersResourceByTokenAndPartnerAddress(BaseResource):
    @if_api_available
    def get(self, token_address: TokenAddress, partner_address: Address) -> Response:
        return self.rest_api.get_pending_transfers(token_address, partner_address)


class StatusResource(BaseResource):
    def get(self) -> Response:
        return self.rest_api.get_status()
