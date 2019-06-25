import structlog

from raiden.constants import UINT64_MAX, UINT256_MAX
from raiden.encoding.encoders import integer
from raiden.encoding.format import make_field


def cmdid(id_):
    return make_field("cmdid", 1, "B", integer(id_, id_))


PROCESSED = 0
PING = 1
PONG = 2
SECRETREQUEST = 3
UNLOCK = 4
LOCKEDTRANSFER = 7
REFUNDTRANSFER = 8
REVEALSECRET = 11
DELIVERED = 12
LOCKEXPIRED = 13
TODEVICE = 14
WITHDRAW_REQUEST = 15
WITHDRAW = 16


log = structlog.get_logger(__name__)


nonce = make_field("nonce", 8, "8s", integer(0, UINT64_MAX))
updating_nonce = make_field("updating_nonce", 8, "8s", integer(0, UINT64_MAX))
other_nonce = make_field("other_nonce", 8, "8s", integer(0, UINT64_MAX))
payment_identifier = make_field("payment_identifier", 8, "8s", integer(0, UINT64_MAX))
chain_id = make_field("chain_id", 32, "32s", integer(0, UINT256_MAX))
message_identifier = make_field("message_identifier", 8, "8s", integer(0, UINT64_MAX))
expiration = make_field("expiration", 32, "32s", integer(0, UINT256_MAX))

token_network_address = make_field("token_network_address", 20, "20s")
token = make_field("token", 20, "20s")
recipient = make_field("recipient", 20, "20s")
target = make_field("target", 20, "20s")
initiator = make_field("initiator", 20, "20s")
participant = make_field("participant", 20, "20s")
updating_participant = make_field("updating_participant", 20, "20s")
other_participant = make_field("other_participant", 20, "20s")
channel_identifier = make_field("channel_identifier", 32, "32s", integer(0, UINT256_MAX))

locksroot = make_field("locksroot", 32, "32s")
secrethash = make_field("secrethash", 32, "32s")
balance_hash = make_field("balance_hash", 32, "32s")
additional_hash = make_field("additional_hash", 32, "32s")
secret = make_field("secret", 32, "32s")
transferred_amount = make_field("transferred_amount", 32, "32s", integer(0, UINT256_MAX))
locked_amount = make_field("locked_amount", 32, "32s", integer(0, UINT256_MAX))
amount = make_field("amount", 32, "32s", integer(0, UINT256_MAX))
reward_amount = make_field("reward_amount", 32, "32s", integer(0, UINT256_MAX))
fee = make_field("fee", 32, "32s", integer(0, UINT256_MAX))
total_withdraw = make_field("total_withdraw", 32, "32s", integer(0, UINT256_MAX))
reveal_timeout = make_field("reveal_timeout", 32, "32s", integer(0, UINT256_MAX))
updating_capacity = make_field("updating_capacity", 32, "32s", integer(0, UINT256_MAX))
other_capacity = make_field("other_capacity", 32, "32s", integer(0, UINT256_MAX))
message_type = make_field("message_type", 32, "32s", integer(0, UINT256_MAX))

signature = make_field("signature", 65, "65s")
non_closing_signature = make_field("non_closing_signature", 65, "65s")
reward_proof_signature = make_field("reward_proof_signature", 65, "65s")
