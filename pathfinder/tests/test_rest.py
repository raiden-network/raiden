import requests
from eth_utils import to_normalized_address

from pathfinder.api.rest import ServiceApi


def test_get_paths_validation(
    api_sut: ServiceApi,
    api_url: str,
    initiator_address: str,
    target_address: str
):
    base_url = api_url + '/paths'

    url = base_url
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'].startswith('Required parameters:')

    url = base_url + '?from=notanaddress&to={}&value=5&num_paths=3'.format(target_address)
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid initiator address: notanaddress'

    url = base_url + '?from={}&to=notanaddress&value=5&num_paths=3'.format(initiator_address)
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Invalid target address: notanaddress'

    url = base_url + '?from={}&to={}&value=5&num_paths=3'.format(
        to_normalized_address(initiator_address),
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Initiator address not checksummed: {}'.format(
        to_normalized_address(initiator_address)
    )

    url = base_url + '?from={}&to={}&value=5&num_paths=3'.format(
        initiator_address,
        to_normalized_address(target_address)
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Target address not checksummed: {}'.format(
        to_normalized_address(target_address)
    )

    url = base_url + '?from={}&to={}&value=-10&num_paths=3'.format(
        initiator_address,
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Payment value must be non-negative: -10'

    url = base_url + '?from={}&to={}&value=10&num_paths=-1'.format(
        initiator_address,
        target_address
    )
    response = requests.get(url)
    assert response.status_code == 400
    assert response.json()['error'] == 'Number of paths must be positive: -1'
