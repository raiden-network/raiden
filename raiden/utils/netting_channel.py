from raiden.utils import sha3


def channel_identifier(participant1, participant2):
    if participant1 < participant2:
        return sha3(participant1 + participant2)
    return sha3(participant2 + participant1)
