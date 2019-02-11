FROM ethereum/client-go:v1.8.22
MAINTAINER Ulrich Petri <ulrich@brainbot.com>

RUN \
    apk add --update python3 python3-dev build-base && \
    rm -rf /var/cache/apk/* && \
    pip3 install web3 click

RUN pip3 install requests

ADD run.py /usr/bin/run.py

ENTRYPOINT ["/usr/bin/run.py"]
