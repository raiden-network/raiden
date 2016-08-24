FROM ubuntu:xenial

MAINTAINER Herman Junge <herman.junge@consensys.net>

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 923F6CA9 \
    && echo "deb http://ppa.launchpad.net/ethereum/ethereum/ubuntu xenial main" \
       | tee -a /etc/apt/sources.list.d/ethereum.list

RUN apt-get update -y \
    && apt-get dist-upgrade -y

RUN apt-get install -y automake build-essential git-core libffi-dev \
       libgmp-dev libssl-dev libtool pkg-config python-dev python-pip solc \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

RUN git clone https://github.com/raiden-network/raiden.git /apps/raiden \
    && cd /apps/raiden \
    && pip install --upgrade -r requirements.txt \
    && python setup.py develop

WORKDIR /apps/raiden

EXPOSE 40001/udp

ENTRYPOINT ["raiden"]
