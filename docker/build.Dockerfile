# backward compatibility:
FROM ubuntu:12.04.5

RUN apt-get update && \
 apt-get install -y curl automake build-essential git-core libffi-dev \ 
 libgmp-dev libssl-dev libtool pkg-config fuse

RUN curl -L -o /usr/bin/solc https://github.com/brainbot-com/solidity-static/releases/download/v0.4.9/solc && \
 chmod +x /usr/bin/solc

RUN apt-get install -y python-software-properties && \
    add-apt-repository ppa:fkrull/deadsnakes-python2.7 && \
    apt-get update && \
    curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py && \
    apt-get -y install python2.7 python2.7-dev && \
    python get-pip.py && \
    pip install virtualenv

RUN virtualenv --always-copy /venv

RUN /bin/bash -c 'source /venv/bin/activate && \ 
    pip install -U pip' 
RUN /bin/bash -c 'source /venv/bin/activate && \
    pip install -U setuptools'

RUN git clone https://github.com/raiden-network/raiden.git /apps/raiden && \
    cd /apps/raiden  && \ 
    /bin/bash -c 'source /venv/bin/activate && \
    pip install .'

RUN mkdir /raiden.AppDir && \
    curl -L -o /raiden.AppDir/AppRun https://github.com/probonopd/AppImageKit/releases/download/6/AppRun_6-x86_64 && \
    curl -L -o AppImageAssistant https://github.com/probonopd/AppImageKit/releases/download/5/AppImageAssistant && \
    chmod +x AppImageAssistant && \
    chmod +x /raiden.AppDir/AppRun

ADD raiden.desktop /raiden.AppDir/raiden.desktop
ADD raiden.svg /raiden.AppDir/raiden.svg

RUN virtualenv --relocatable /venv &&\
    cp -r /venv /raiden.AppDir/usr

# FIXME: dev dependency
RUN apt-get -y install vim strace
