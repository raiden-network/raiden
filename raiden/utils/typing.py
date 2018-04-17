# -*- coding: utf-8 -*-
from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import NewType

T_Address = bytes
Address = NewType('Address', bytes)

T_BlockExpiration = int
BlockExpiration = NewType('BlockExpiration', int)

T_BlockNumber = int
BlockNumber = NewType('BlockNumber', int)

T_BlockTimeout = int
BlockTimeout = NewType('BlockNumber', int)

T_ChannelID = T_Address
ChannelID = NewType('ChannelID', Address)

T_Keccak256 = bytes
Keccak256 = NewType('Keccak256', bytes)

T_Secret = bytes
Secret = NewType('Secret', bytes)

T_Signature = bytes
Signature = NewType('Signature', bytes)

T_TokenAmount = int
TokenAmount = NewType('TokenAmount', int)
