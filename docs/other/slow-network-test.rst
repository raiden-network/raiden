Testing Raiden on a slow network
================================

In order to analyze Raiden performance on slow networks, it is useful to have a way of
introducing latencies. On Linux this can be achieved by making use of the ``tc`` utility.

.. note::

   These instructions are Linux-specific. You will need the ``ip``, ``tc`` and
   ``iptables`` utilities. If you're using Arch Linux, you can get these by
   installing the ``iproute2`` and ``iptables`` packages.

The following script can be used to prepare the interfaces:

.. code:: bash

    #!/usr/bin/env bash

    # The network interface to the outside, i.e. the Internet.
    IFACE="wlan0"

    IP=$(ip addr show dev ${IFACE} | grep -Po 'inet \K[\d.]+')
    NSNAME="slow"

    VETHA="veth-a"
    VETHB="veth-b"
    VETHPREFIX="192.168.163.0/24"
    VETHNETMASK="255.255.255.0"
    VETHAIP="192.168.163.1"
    VETHBIP="192.168.163.254"

    ip netns add ${NSNAME}
    ip link add ${VETHA} type veth peer name ${VETHB}
    ip link set ${VETHA} netns ${NSNAME}

    ip netns exec ${NSNAME} ip link set dev ${VETHA} up
    ip netns exec ${NSNAME} ip addr add ${VETHAIP}/24 brd ${VETHNETMASK} dev ${VETHA}

    ip link set dev ${VETHB} up
    ip addr add ${VETHBIP}/24 brd ${VETHNETMASK} dev ${VETHB}

    ip netns exec ${NSNAME} route add default gw ${VETHBIP} dev ${VETHA}
    echo 1 > /proc/sys/net/ipv4/ip_forward
    iptables -t nat -A POSTROUTING -s ${VETHPREFIX} -o ${IFACE} -j SNAT --to-source ${IP}


.. note::

   All of the things here require root privileges.

The script will create a virtual Ethernet interface pair (veth-a, veth-b) and move one of the
interfaces (veth-b) into a newly created network namespace. After setting up the interfaces'
addresses and adding the default route, the script will configure packet forwarding to the
real interface (wlan0) connected to the Internet.

Once the interfaces are prepared, we can simulate a network delay of, say, 200ms by
using tc (replace ``${VETHB}`` with its value defined in the above script):

.. code:: bash

    tc qdisc add dev ${VETHB} root netem delay 200ms

Now we just need to start Raiden from within the network namespace that we created:

.. code:: bash

    ip netns exec ${NSNAME} bash
    # switch to a normal user
    # enter virtual environment
    # run Raiden
