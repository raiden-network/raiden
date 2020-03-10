from typing import Any, Dict, Optional

from raiden.constants import RECEIPT_FAILURE_CODE
from raiden.network.rpc.client import TransactionMined


def was_transaction_successfully_mined(transaction: TransactionMined) -> Optional[Dict[str, Any]]:
    """ `True` if the transaction was successfully mined, `False` otherwise. """
    if "status" not in transaction.receipt:
        # This should never happen. Raiden checks ethereum client for compatibility at startup
        raise AssertionError(
            "Transaction receipt does not contain a status field. Upgrade your client"
        )

    return transaction.receipt["status"] != RECEIPT_FAILURE_CODE
