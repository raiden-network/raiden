FROM python:2.7
MAINTAINER Ulrich Petri <ulrich@brainbot.com>

RUN \
    apt update && \
    apt install -y build-essential curl git libffi-dev libgmp-dev libssl-dev libtool pkg-config && \
    rm -rf /var/lib/apt/lists/* && \
    curl -L -o /usr/bin/solc https://github.com/ethereum/solidity/releases/download/v0.4.13/solc-static-linux && \
    chmod +x /usr/bin/solc && \
    git clone https://github.com/raiden-network/raiden.git /app && \
    pip install -r /app/requirements.txt -e /app

WORKDIR /app

RUN python setup.py compile_contracts

ADD run.py /usr/local/bin


ENTRYPOINT ["/usr/local/bin/run.py"]
