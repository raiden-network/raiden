FROM ubuntu:xenial

LABEL maintainer="André Vitor de Lima Matos <andre@brainbot.com>"
LABEL contributor="Herman Junge <herman.junge@consensys.net>"

RUN apt-key adv --keyserver keyserver.ubuntu.com --recv-keys 923F6CA9 && \
    echo "deb http://ppa.launchpad.net/ethereum/ethereum/ubuntu xenial main" | \
    tee -a /etc/apt/sources.list.d/ethereum.list

RUN apt-get update -y && \
    apt-get dist-upgrade -y

RUN apt-get install -y automake build-essential git-core libffi-dev \
        libgmp-dev libssl-dev libtool pkg-config python-dev python-pip solc && \
    rm -rf /var/lib/apt/lists/*

RUN pip install --upgrade pip

COPY ./repo/requirements.txt /apps/requirements.txt
RUN cd /apps && \
    pip install --upgrade -r requirements.txt

COPY ./repo/ /apps/raiden
RUN cd /apps/raiden && \
    python setup.py develop

WORKDIR /apps/raiden

EXPOSE 40001/udp 5001

ENTRYPOINT ["raiden"]

