# -*- coding: utf-8 -*-
from typing import *  # NOQA pylint:disable=wildcard-import,unused-wildcard-import
from typing import NewType

T_Address = bytes
Address = NewType('Address', T_Address)

T_BlockExpiration = int
BlockExpiration = NewType('BlockExpiration', T_BlockExpiration)

T_BlockNumber = int
BlockNumber = NewType('BlockNumber', T_BlockNumber)

T_BlockTimeout = int
BlockTimeout = NewType('BlockNumber', T_BlockTimeout)

T_ChannelID = bytes
ChannelID = NewType('ChannelID', T_ChannelID)

T_MessageID = int
MessageID = NewType('MessageID', T_MessageID)

T_Keccak256 = bytes
Keccak256 = NewType('Keccak256', T_Keccak256)

T_TokenAmount = int
TokenAmount = NewType('TokenAmount', T_TokenAmount)

T_Secret = bytes
Secret = NewType('Secret', T_Secret)

T_Signature = bytes
Signature = NewType('Signature', T_Signature)
