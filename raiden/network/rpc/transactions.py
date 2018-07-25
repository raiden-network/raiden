def check_transaction_threw(client, transaction_hash: bytes):
    """Check if the transaction threw/reverted or if it executed properly
       Returns None in case of success and the transaction receipt if the
       transaction's status indicator is 0x0.
    """
    receipt = client.get_transaction_receipt(transaction_hash)

    if 'status' not in receipt:
        raise ValueError(
            'Transaction receipt does not contain a status field. Upgrade your client',
        )

    if receipt['status'] == 0:
        return receipt

    return None
