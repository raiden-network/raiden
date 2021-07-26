from dataclasses import dataclass

from raiden.utils.typing import ABI, Address, BlockNumber, GasMeasurements, Optional, TypeVar

T = TypeVar("T")


@dataclass
class SmartContractMetadata:
    """Basic metadata of a smart contract."""

    # If the user deployed the smart contract, the mined block is unknown.
    deployed_at: Optional[BlockNumber]

    # Value to use as `fromBlock` for filters. If the deployed block number is
    # know it must be used, otherwise a hard fork block number can be used as a
    # lower bound.
    #
    # The deployed_at must be used because querying for logs before the smart
    # contract is deployed has bad performance (see #3958), and values larger
    # than the deployed_at will potentially miss logs.
    filters_start_at: BlockNumber

    # Make this a generic once https://github.com/python/mypy/issues/7520 is fixed
    address: Address

    abi: ABI
    gas_measurements: GasMeasurements

    def __post_init__(self) -> None:
        is_filter_start_valid = (
            self.deployed_at is None or self.deployed_at == self.filters_start_at
        )
        if not is_filter_start_valid:
            raise ValueError(
                "The deployed_at is known, the filters should start at that exact block"
            )
