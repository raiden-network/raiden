import pytest
from tools.raiddit.generate_claims import ClaimGenerator

from raiden.tests.utils.factories import UNIT_CHAIN_ID, UNIT_OPERATOR_SIGNER


@pytest.fixture
def hub_address():
    return None


@pytest.fixture
def claim_generator(hub_address):
    generator = ClaimGenerator(
        operator_signer=UNIT_OPERATOR_SIGNER, chain_id=UNIT_CHAIN_ID, hub_address=hub_address
    )
    return generator
