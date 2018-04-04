# -*- coding: utf-8 -*-
from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import NewType

Address = NewType('Address', bytes)

BlockExpiration = NewType('BlockExpiration', int)
BlockNumber = NewType('BlockNumber', int)
BlockTimeout = NewType('BlockNumber', int)
ChannelID = NewType('ChannelID', Address)
Keccak256 = NewType('Keccak256', bytes)
Secret = NewType('Secret', bytes)
Signature = NewType('Signature', bytes)
TokenAmount = NewType('TokenAmount', int)
