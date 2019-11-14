from typing import Any, Dict, Optional

from raiden.constants import RECEIPT_FAILURE_CODE


def check_transaction_threw(receipt: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Check if the transaction threw/reverted or if it executed properly by reading
       the transaction receipt.
       Returns None in case of success and the transaction receipt if the
       transaction's status indicator is 0x0.
    """
    if "status" not in receipt:
        # This should never happen. Raiden checks ethereum client for compatibility at startup
        raise AssertionError(
            "Transaction receipt does not contain a status field. Upgrade your client"
        )

    if receipt["status"] == RECEIPT_FAILURE_CODE:
        return receipt

    return None
