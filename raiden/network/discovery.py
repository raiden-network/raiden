# -*- coding: utf8 -*-
from raiden.utils import isaddress, privtoaddr, sha3


class Discovery(object):
    """ Mock mapping address: host, port """

    def __init__(self):
        self.nodeid_hostport = dict()

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)  # fixme, this is H(pubkey)
        self.nodeid_hostport[nodeid] = (host, port)

    def get(self, nodeid):
        return self.nodeid_hostport[nodeid]

    def nodeid_by_host_port(self, host_port):
        for nodeid, value_hostport in self.nodeid_hostport.items():
            if value_hostport == host_port:
                return nodeid

        assert False


class PredictiveDiscovery(Discovery):
    """
    Initialized with a list of `(host, num_nodes, start_port)` tuples,
    this discovery is able to predict the address for any
    (predictable) node-id.

    This avoids the need of a shared discovery instance, while still
    providing the convenience of a mock-like service.

    Note, that start_port can be omitted.
    """

    def __init__(self, mapping, default_start_port=40001):
        super(PredictiveDiscovery, self).__init__()

        # [('127.0.0.1', 36), ('127.0.0.2', 15), ...]
        for entry in mapping:
            if len(entry) == 3:
                start_port = entry[-1]
            else:
                start_port = default_start_port

            (host, num_nodes) = entry[:2]

            for i in range(num_nodes):
                host_port = (host, start_port + i)
                nodeid = privtoaddr(sha3("{}:{}".format(*host_port)))
                self.nodeid_hostport[nodeid] = host_port

    def register(self, *args):
        pass
