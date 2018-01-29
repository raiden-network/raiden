# -*- coding: utf-8 -*-
from binascii import unhexlify

from raiden.utils import data_encoder
from raiden.settings import GAS_LIMIT


def check_transaction_threw(client, transaction_hash):
    """Check if the transaction threw/reverted or if it executed properly
       Returns None in case of success and the transaction receipt if the
       transaction's status indicator is 0x0.
    """
    encoded_transaction = data_encoder(unhexlify(transaction_hash))
    receipt = client.call('eth_getTransactionReceipt', encoded_transaction)

    if 'status' not in receipt:
        raise ValueError(
            'Transaction receipt does not contain a status field. Upgrade your client'
        )

    if receipt['status'] == '0x0':
        return receipt

    return None


def estimate_and_transact(proxy, function_name, *args):
    """Estimate gas using eth_estimateGas. Multiply by 2 to make sure sufficient gas is provided
    Limit maximum gas to GAS_LIMIT to avoid exceeding blockgas limit
    """
    # pylint: disable=unused-argument

    # XXX: From Byzantium and on estimate gas is not giving an accurate estimation
    #      and as such we not longer utilize its result but use the GAS_LIMIT in
    #      all transactions. With the revert() call not consuming all given gas that
    #      is not that bad
    #
    # estimated_gas = callobj.estimate_gas(
    #     *args,
    #     startgas=startgas,
    #     gasprice=gasprice
    # )
    estimated_gas = GAS_LIMIT
    transaction_hash = proxy.transact(
        function_name,
        *args,
        startgas=estimated_gas
    )
    return transaction_hash
