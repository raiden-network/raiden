FROM python:2.7
MAINTAINER Ulrich Petri <ulrich@brainbot.com>

RUN \
    apt update && \
    apt install -y build-essential curl git libffi-dev libgmp-dev libssl-dev libtool pkg-config apt-transport-https lsb-release && \
    curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - && \
    echo 'deb https://deb.nodesource.com/node_8.x jessie main' > /etc/apt/sources.list.d/nodesource.list && \
    echo 'deb-src https://deb.nodesource.com/node_8.x jessie main' >> /etc/apt/sources.list.d/nodesource.list && \
    apt update && \
    apt install nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    curl -L -o /usr/bin/solc https://github.com/ethereum/solidity/releases/download/v0.4.13/solc-static-linux && \
    chmod +x /usr/bin/solc

RUN \
    git clone -b testnet_transfers https://github.com/ulope/raiden.git /app && \
    pip install -r /app/requirements.txt -e /app


WORKDIR /app

RUN \
    python setup.py compile_contracts && \
    python setup.py compile_webui

ADD run.py /usr/local/bin


ENTRYPOINT ["/usr/local/bin/run.py"]
