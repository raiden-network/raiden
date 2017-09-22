# -*- coding: utf-8 -*-

UINT64_MAX = 2 ** 64 - 1
UINT64_MIN = 0

INT64_MAX = 2 ** 63 - 1
INT64_MIN = -(2 ** 63)

UINT256_MAX = 2 ** 256 - 1

# Deployed to Ropsten revival on 2017-09-03 from commit f4f8dcbe791b7be8bc15475f79ad9cbbfe15435b
ROPSTEN_REGISTRY_ADDRESS = '68e1b6ed7d2670e2211a585d68acfa8b60ccb828'
ROPSTEN_DISCOVERY_ADDRESS = '826259ce4dcc2802c92780e3d79d43ff3cf3f151'

DISCOVERY_REGISTRATION_GAS = 500000

MINUTE_SEC = 60
MINUTE_MS = 60 * 1000

NETTINGCHANNEL_SETTLE_TIMEOUT_MIN = 6
# The maximum settle timeout is chosen as something above
# 1 year with the assumption of very fast block times of 12 seconds.
# There is a maximum to avoidpotential overflows as described here:
# https://github.com/raiden-network/raiden/issues/1038
NETTINGCHANNEL_SETTLE_TIMEOUT_MAX = 2700000

# TODO: add this as an attribute of the transport class
UDP_MAX_MESSAGE_SIZE = 1200

MAINNET = 'mainnet'
ROPSTEN = 'ropsten'
RINKEBY = 'rinkeby'
KOVAN = 'kovan'

ID_TO_NETWORKNAME = {
    1: MAINNET,
    3: ROPSTEN,
    4: RINKEBY,
    42: KOVAN,
}

NETWORKNAME_TO_ID = {
    name: id
    for id, name in ID_TO_NETWORKNAME.iteritems()
}
