FROM python:2.7
MAINTAINER Ulrich Petri <ulrich@brainbot.com>

ARG SOLC_RELEASE=0.4.21

RUN \
    apt update && \
    apt install -y build-essential curl git libffi-dev libgmp-dev libssl-dev libtool pkg-config apt-transport-https lsb-release && \
    curl -s https://deb.nodesource.com/gpgkey/nodesource.gpg.key | apt-key add - && \
    echo 'deb https://deb.nodesource.com/node_8.x jessie main' > /etc/apt/sources.list.d/nodesource.list && \
    echo 'deb-src https://deb.nodesource.com/node_8.x jessie main' >> /etc/apt/sources.list.d/nodesource.list && \
    apt update && \
    apt install nodejs && \
    rm -rf /var/lib/apt/lists/* && \
    curl -L -o /usr/bin/solc https://github.com/ethereum/solidity/releases/download/v${SOLC_RELEASE}/solc-static-linux && \
    chmod +x /usr/bin/solc

# These are defined down here to avoid rebuilding the "apt" part on repo/branch change
ARG REPO=raiden-network/raiden
ARG BRANCH=master

# This is a "hack" to automatically invalidate the cache in case there are new commits
ADD https://api.github.com/repos/${REPO}/commits/${BRANCH} /dev/null
RUN \
    echo Cloning ${REPO}@${BRANCH} && \
    git clone -b ${BRANCH} https://github.com/${REPO}.git /app && \
    pip --version && \
    pip install -r /app/requirements.txt -e /app && \
    pip install python-logstash && \
    rm -rf /root/.cache/pip

WORKDIR /app

RUN \
    python setup.py compile_webui && \
    rm -rf /root/.npm/_cacache

ADD run_raiden.py /usr/local/bin
ADD raiden /usr/local/bin
ADD raiden_echo_node /usr/local/bin


ENTRYPOINT ["/usr/local/bin/run_raiden.py"]
