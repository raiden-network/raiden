FROM python:3.7

MAINTAINER Ulrich Petri <ulrich@brainbot.com>

RUN \
    apt update && \
    apt install -y libssl-dev build-essential automake pkg-config libtool libffi-dev libgmp-dev && \
    pip3 install ethereum coincurve click && \
    rm -rf /var/lib/apt/lists/*

ADD mkkey.py /usr/bin/

ENTRYPOINT ["/usr/bin/mkkey.py"]
