# -*- coding: utf-8 -*-
from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import NewType

_Address = bytes
Address = NewType('Address', bytes)

_BlockExpiration = int
BlockExpiration = NewType('BlockExpiration', int)

_BlockNumber = int
BlockNumber = NewType('BlockNumber', int)

_BlockTimeout = int
BlockTimeout = NewType('BlockNumber', int)

_ChannelID = _Address
ChannelID = NewType('ChannelID', Address)

_Keccak256 = bytes
Keccak256 = NewType('Keccak256', bytes)

_Secret = bytes
Secret = NewType('Secret', bytes)

_Signature = bytes
Signature = NewType('Signature', bytes)

_TokenAmount = int
TokenAmount = NewType('TokenAmount', int)
