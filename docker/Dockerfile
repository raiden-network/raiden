FROM ubuntu:xenial

MAINTAINER Herman Junge <herman.junge@consensys.net>

RUN apt-get update -y \
    && apt-get upgrade -q -y \
    && apt-get dist-upgrade -q -y \
    && apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 923F6CA9 \
    && echo "deb http://ppa.launchpad.net/ethereum/ethereum/ubuntu xenial main" \
       | tee -a /etc/apt/sources.list.d/ethereum.list \
    && apt-get update -q -y \
    && apt-get install -y automake build-essential git-core libffi-dev \
       libgmp-dev libssl-dev libtool pkg-config python-dev python-pip solc \
    && pip install --upgrade pip \
    && rm -rf /var/lib/apt/lists/* \
    && git clone https://github.com/ethereum/pyrlp /apps/pyrlp \
    && cd /apps/pyrlp \
    && pip install -e . \
    && git clone https://github.com/ethereum/pydevp2p /apps/pydevp2p \
    && cd /apps/pydevp2p \
    && pip install -e . \
    && git clone https://github.com/ethereum/pyethereum /apps/pyethereum \
    && cd /apps/pyethereum \
    && pip install -e . \
    && git clone https://github.com/ethereum/pyethapp /apps/pyethapp \
    && cd /apps/pyethapp \
    && pip install -e . \
    && git clone https://github.com/raiden-network/raiden.git /apps/raiden \
    && cd /apps/raiden \
    && python setup.py develop \
    && apt-get purge -y automake build-essential git-core \
    && apt-get -y autoremove

WORKDIR /apps/raiden

ENTRYPOINT ["raiden"]
