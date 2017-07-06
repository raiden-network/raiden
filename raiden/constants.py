# -*- coding: utf-8 -*-

UINT64_MAX = 2 ** 64 - 1
UINT64_MIN = 0

INT64_MAX = 2 ** 63 - 1
INT64_MIN = -(2 ** 63)

UINT256_MAX = 2 ** 256 - 1

# Deployed to Ropsten revival on 2017-06-19 from commit 2677298a69c1b1f35b9ab26beafe457acfdcc0ee
ROPSTEN_REGISTRY_ADDRESS = 'aff1f958c69a6820b08a02549ff9041629ae8257'
ROPSTEN_DISCOVERY_ADDRESS = 'cf56165f4f6e8ec38bb463854c1fe28a5d320f4f'

MINUTE_SEC = 60
MINUTE_MS = 60 * 1000

NETTINGCHANNEL_SETTLE_TIMEOUT_MIN = 6

# TODO: add this as an attribute of the transport class
UDP_MAX_MESSAGE_SIZE = 1200
