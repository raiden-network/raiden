# -*- coding: utf-8 -*-
import pytest
from ethereum.utils import normalize_address
from ethereum.tools.tester import TransactionFailed
from coincurve import PrivateKey

from raiden.messages import Lock, MediatedTransfer
from raiden.tests.utils.messages import (
    HASHLOCK_FOR_MERKLETREE,
    HASHLOCKS_SECRESTS,
    make_direct_transfer,
    make_lock,
)
from raiden.tests.utils.transfer import make_mediated_transfer
from raiden.transfer.merkle_tree import (
    compute_layers,
    compute_merkleproof_for,
    merkleroot,
)
from raiden.transfer.state_change import Block
from raiden.transfer.state import MerkleTreeState
from raiden.utils import sha3, privatekey_to_address


def test_withdraw(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_channels,
        tester_chain,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    lock_amount = 31
    lock_expiration = tester_chain.block.number + reveal_timeout + 5
    secret = b'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock0 = Lock(lock_amount, lock_expiration, hashlock)

    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock0,
        pkey0,
        tester_chain.block.number,
        secret,
    )

    # withdraw the pending transfer sent to us by our partner
    proof = channel1.partner_state.compute_proof_for_lock(
        secret,
        mediated0.lock,
    )

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=1)

    nettingchannel.withdraw(
        proof.lock_encoded,
        b''.join(proof.merkle_proof),
        proof.secret,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock0.amount
    balance1 = initial_balance1 + deposit + lock0.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


# This test must not use tester_channels since these proxies do automatic
# mining
def test_withdraw_at_settlement_block(
        deposit,
        settle_timeout,
        tester_nettingcontracts,
        tester_chain,
        tester_token):

    """ It must be possible to unlock a lock up to and including the settlment
    block.
    """

    pkey0, pkey1, nettingchannel = tester_nettingcontracts[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    lock_amount = 31
    lock_expiration = tester_chain.block.number + settle_timeout
    secret = b'settlementsettlementsettlementse'
    hashlock = sha3(secret)

    lock0 = Lock(
        amount=lock_amount,
        expiration=lock_expiration,
        hashlock=hashlock,
    )
    lock0_bytes = bytes(lock0.as_bytes)
    lock0_hash = sha3(lock0_bytes)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))

    mediated0 = MediatedTransfer(
        identifier=1,
        nonce=nonce,
        token=tester_token.address,
        channel=normalize_address(nettingchannel.address),
        transferred_amount=0,
        recipient=address1,
        locksroot=lock0_hash,
        lock=lock0,
        target=address1,
        initiator=address0,
        fee=0,
    )

    sign_key0 = PrivateKey(pkey0)
    mediated0.sign(sign_key0, address0)

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    block_until_settlement_end = lock_expiration - tester_chain.block.number
    tester_chain.mine(number_of_blocks=block_until_settlement_end)

    assert lock_expiration == tester_chain.block.number
    nettingchannel.withdraw(
        lock0_bytes,
        b'',  # the lock itself it the root, the proof is empty
        secret,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock0.amount
    balance1 = initial_balance1 + deposit + lock0.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_withdraw_expired_lock(reveal_timeout, tester_channels, tester_chain):
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    lock_timeout = reveal_timeout + 5
    lock_expiration = tester_chain.block.number + lock_timeout
    secret = b'expiredlockexpiredlockexpiredloc'
    hashlock = sha3(secret)
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock1 = Lock(amount=31, expiration=lock_expiration, hashlock=hashlock)

    mediated0 = make_mediated_transfer(
        channel1,
        channel0,
        privatekey_to_address(pkey0),
        privatekey_to_address(pkey1),
        lock1,
        pkey1,
        tester_chain.block.number,
        secret,
    )

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey0,
    )

    # expire the lock
    tester_chain.mine(number_of_blocks=lock_timeout + 1)

    unlock_proofs = list(channel0.partner_state.get_known_unlocks())
    proof = unlock_proofs[0]

    with pytest.raises(TransactionFailed):
        nettingchannel.withdraw(
            proof.lock_encoded,
            b''.join(proof.merkle_proof),
            proof.secret,
            sender=pkey0,
        )


@pytest.mark.parametrize('settle_timeout', [50])
@pytest.mark.parametrize('reveal_timeout', [5])
def test_withdraw_both_participants(
        deposit,
        settle_timeout,
        reveal_timeout,
        tester_channels,
        tester_chain,
        tester_token):

    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    secret = b'secretsecretsecretsecretsecretse'
    hashlock = sha3(secret)

    lock_amount = 31
    lock01_expiration = tester_chain.block.number + settle_timeout - 1 * reveal_timeout
    lock10_expiration = tester_chain.block.number + settle_timeout - 2 * reveal_timeout

    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)

    # using the same hashlock and amount is intentional
    lock01 = Lock(lock_amount, lock01_expiration, hashlock)
    lock10 = Lock(lock_amount, lock10_expiration, hashlock)

    mediated01 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock01,
        pkey0,
        tester_chain.block.number,
        secret,
    )

    mediated10 = make_mediated_transfer(
        channel1,
        channel0,
        address1,
        address0,
        lock10,
        pkey1,
        tester_chain.block.number,
        secret,
    )

    mediated01_hash = sha3(mediated01.packed().data[:-65])
    nettingchannel.close(
        mediated01.nonce,
        mediated01.transferred_amount,
        mediated01.locksroot,
        mediated01_hash,
        mediated01.signature,
        sender=pkey1,
    )
    tester_chain.mine(number_of_blocks=1)

    mediated10_hash = sha3(mediated10.packed().data[:-65])
    nettingchannel.updateTransfer(
        mediated10.nonce,
        mediated10.transferred_amount,
        mediated10.locksroot,
        mediated10_hash,
        mediated10.signature,
        sender=pkey0,
    )
    tester_chain.mine(number_of_blocks=1)

    proof01 = channel1.partner_state.compute_proof_for_lock(
        secret,
        mediated01.lock,
    )
    nettingchannel.withdraw(
        proof01.lock_encoded,
        b''.join(proof01.merkle_proof),
        proof01.secret,
        sender=pkey1,
    )

    proof10 = channel0.partner_state.compute_proof_for_lock(
        secret,
        mediated10.lock,
    )
    nettingchannel.withdraw(
        proof10.lock_encoded,
        b''.join(proof10.merkle_proof),
        proof10.secret,
        sender=pkey0,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock01.amount + lock10.amount
    balance1 = initial_balance1 + deposit + lock01.amount - lock10.amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0


def test_withdraw_twice(reveal_timeout, tester_channels, tester_chain):
    """ A lock can be withdrawn only once, the second try must fail. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]

    lock_expiration = tester_chain.block.number + reveal_timeout + 5
    secret = b'secretsecretsecretsecretsecretse'
    new_block = Block(tester_chain.block.number)
    channel0.state_transition(new_block)
    channel1.state_transition(new_block)
    lock = Lock(17, lock_expiration, sha3(secret))

    mediated0 = make_mediated_transfer(
        channel1,
        channel0,
        privatekey_to_address(pkey1),
        privatekey_to_address(pkey0),
        lock,
        pkey1,
        tester_chain.block.number,
        secret,
    )

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.close(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey0,
    )

    unlock_proofs = list(channel0.partner_state.get_known_unlocks())
    proof = unlock_proofs[0]

    nettingchannel.withdraw(
        proof.lock_encoded,
        b''.join(proof.merkle_proof),
        proof.secret,
        sender=pkey0,
    )

    with pytest.raises(TransactionFailed):
        nettingchannel.withdraw(
            proof.lock_encoded,
            b''.join(proof.merkle_proof),
            proof.secret,
            sender=pkey0,
        )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_fails_with_partial_merkle_proof(
        tree,
        tester_channels,
        tester_chain,
        settle_timeout):

    """ withdraw must fail if informed proof is not complete. """
    pkey0, pkey1, nettingchannel, channel0, _ = tester_channels[0]

    current_block = tester_chain.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    leaves = [sha3(lock.as_bytes) for lock in locks]
    layers = compute_layers(leaves)
    merkle_tree = MerkleTreeState(layers)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        channel=channel0.channel_address,
        locksroot=merkleroot(merkle_tree),
        recipient=privatekey_to_address(pkey1)
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0)
    direct_transfer.sign(sign_key, address)

    direct_transfer_hash = sha3(direct_transfer.packed().data[:-65])
    nettingchannel.close(
        direct_transfer.nonce,
        direct_transfer.transferred_amount,
        direct_transfer.locksroot,
        direct_transfer_hash,
        direct_transfer.signature,
        sender=pkey1,
    )

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]
        lock_encoded = lock.as_bytes
        merkle_proof = compute_merkleproof_for(merkle_tree, sha3(lock_encoded))

        # withdraw must fail regardless of which part of the proof is removed
        for hash_ in merkle_proof:
            tampered_proof = list(merkle_proof)
            tampered_proof.remove(hash_)

            with pytest.raises(TransactionFailed):
                nettingchannel.withdraw(
                    lock_encoded,
                    b''.join(tampered_proof),
                    secret,
                    sender=pkey1,
                )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_tampered_merkle_proof(tree, tester_channels, tester_chain, settle_timeout):
    """ withdraw must fail if the proof is tampered. """
    pkey0, pkey1, nettingchannel, channel0, _ = tester_channels[0]

    current_block = tester_chain.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    leaves = [sha3(lock.as_bytes) for lock in locks]
    layers = compute_layers(leaves)
    merkle_tree = MerkleTreeState(layers)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        channel=channel0.channel_address,
        locksroot=merkleroot(merkle_tree),
        recipient=privatekey_to_address(pkey1)
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0)
    direct_transfer.sign(sign_key, address)

    direct_transfer_hash = sha3(direct_transfer.packed().data[:-65])
    nettingchannel.close(
        direct_transfer.nonce,
        direct_transfer.transferred_amount,
        direct_transfer.locksroot,
        direct_transfer_hash,
        direct_transfer.signature,
        sender=pkey1,
    )

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]

        lock_encoded = lock.as_bytes
        merkle_proof = compute_merkleproof_for(merkle_tree, sha3(lock_encoded))

        # withdraw must fail regardless of which part of the proof is tampered
        for pos, hash_ in enumerate(merkle_proof):
            # changing arbitrary bytes from the proof
            tampered_hash = bytearray(hash_)
            tampered_hash[6], tampered_hash[7] = tampered_hash[7], tampered_hash[6]

            tampered_proof = list(merkle_proof)
            tampered_proof[pos] = tampered_hash

            joiner = b''
            with pytest.raises(TransactionFailed):
                nettingchannel.withdraw(
                    lock_encoded,
                    joiner.join(tampered_proof),
                    secret,
                    sender=pkey1,
                )


@pytest.mark.parametrize('tree', HASHLOCK_FOR_MERKLETREE)
def test_withdraw_tampered_lock_amount(
        tree,
        tester_channels,
        tester_chain,
        tester_token,
        settle_timeout):

    """ withdraw must fail if the lock amonut is tampered. """
    pkey0, pkey1, nettingchannel, channel0, _ = tester_channels[0]

    current_block = tester_chain.block.number
    expiration = current_block + settle_timeout - 1
    locks = [
        make_lock(
            hashlock=hashlock,
            expiration=expiration,
        )
        for hashlock in tree
    ]

    leaves = [sha3(lock.as_bytes) for lock in locks]
    layers = compute_layers(leaves)
    merkle_tree = MerkleTreeState(layers)

    opened_block = nettingchannel.opened(sender=pkey0)
    nonce = 1 + (opened_block * (2 ** 32))
    direct_transfer = make_direct_transfer(
        nonce=nonce,
        channel=channel0.channel_address,
        locksroot=merkleroot(merkle_tree),
        token=tester_token.address,
        recipient=privatekey_to_address(pkey1)
    )

    address = privatekey_to_address(pkey0)
    sign_key = PrivateKey(pkey0)
    direct_transfer.sign(sign_key, address)

    direct_transfer_hash = sha3(direct_transfer.packed().data[:-65])
    nettingchannel.close(
        direct_transfer.nonce,
        direct_transfer.transferred_amount,
        direct_transfer.locksroot,
        direct_transfer_hash,
        direct_transfer.signature,
        sender=pkey1,
    )

    for lock in locks:
        secret = HASHLOCKS_SECRESTS[lock.hashlock]

        lock_encoded = lock.as_bytes
        merkle_proof = compute_merkleproof_for(merkle_tree, sha3(lock_encoded))

        tampered_lock = make_lock(
            amount=lock.amount * 100,
            hashlock=lock.hashlock,
            expiration=lock.expiration,
        )
        tampered_lock_encoded = sha3(tampered_lock.as_bytes)

        with pytest.raises(TransactionFailed):
            nettingchannel.withdraw(
                tampered_lock_encoded,
                b''.join(merkle_proof),
                secret,
                sender=pkey1,
            )


def test_withdraw_lock_with_a_large_expiration(
        deposit,
        tester_channels,
        tester_chain,
        tester_token,
        settle_timeout):

    """ Withdraw must accept a lock that expires after the settlement period. """
    pkey0, pkey1, nettingchannel, channel0, channel1 = tester_channels[0]
    address0 = privatekey_to_address(pkey0)
    address1 = privatekey_to_address(pkey1)

    initial_balance0 = tester_token.balanceOf(address0, sender=pkey0)
    initial_balance1 = tester_token.balanceOf(address1, sender=pkey0)

    # use a really large expiration
    lock_expiration = tester_chain.block.number + settle_timeout * 5

    # work around for the python expiration validation
    bad_block_number = lock_expiration - 10
    channel0.state_transition(Block(bad_block_number))

    lock_amount = 29
    secret = sha3(b'test_withdraw_lock_with_a_large_expiration')
    lock_hashlock = sha3(secret)
    lock = Lock(
        amount=lock_amount,
        expiration=lock_expiration,
        hashlock=lock_hashlock,
    )
    mediated0 = make_mediated_transfer(
        channel0,
        channel1,
        address0,
        address1,
        lock,
        pkey0,
        bad_block_number,
        secret,
    )

    nettingchannel.close(sender=pkey0)

    mediated0_hash = sha3(mediated0.packed().data[:-65])
    nettingchannel.updateTransfer(
        mediated0.nonce,
        mediated0.transferred_amount,
        mediated0.locksroot,
        mediated0_hash,
        mediated0.signature,
        sender=pkey1,
    )

    unlock_proofs = list(channel1.partner_state.get_known_unlocks())
    proof = unlock_proofs[0]

    nettingchannel.withdraw(
        proof.lock_encoded,
        b''.join(proof.merkle_proof),
        proof.secret,
        sender=pkey1,
    )

    tester_chain.mine(number_of_blocks=settle_timeout + 1)
    nettingchannel.settle(sender=pkey0)

    balance0 = initial_balance0 + deposit - lock_amount
    balance1 = initial_balance1 + deposit + lock_amount
    assert tester_token.balanceOf(address0, sender=pkey0) == balance0
    assert tester_token.balanceOf(address1, sender=pkey0) == balance1
    assert tester_token.balanceOf(nettingchannel.address, sender=pkey0) == 0
