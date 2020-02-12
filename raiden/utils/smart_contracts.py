from raiden import constants


def safe_gas_limit(*estimates: int) -> int:
    """ Calculates a safe gas limit for a number of gas estimates
    including a security margin
    """
    assert None not in estimates, "if estimateGas returned None it should not reach here"
    calculated_limit = max(estimates)
    return int(calculated_limit * constants.GAS_FACTOR)
