# -*- coding: utf8 -*-
from raiden.utils import isaddress, pex


class Discovery(object):
    """ Mock mapping address: host, port """

    def __init__(self):
        self.nodeid_hostport = dict()

    def register(self, nodeid, host, port):
        assert isaddress(nodeid)  # fixme, this is H(pubkey)
        self.nodeid_hostport[nodeid] = (host, port)

    def get(self, nodeid):
        try:
            return self.nodeid_hostport[nodeid]
        except KeyError:
            raise KeyError('Unknow address {}'.format(pex(nodeid)))

    def nodeid_by_host_port(self, host_port):
        for nodeid, value_hostport in self.nodeid_hostport.items():
            if value_hostport == host_port:
                return nodeid

        assert False
