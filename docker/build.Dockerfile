# backward compatibility:
FROM ubuntu:12.04.5

# install build dependencies
RUN apt-get update && \
 apt-get install -y curl wget automake build-essential git-core libffi-dev \
 libgmp-dev libssl-dev libtool pkg-config fuse libsqlite3-dev

# prepare AppDir
RUN bash -c 'mkdir -p /raiden.AppDir/usr/{local,bin,share,lib}/'

WORKDIR /raiden.AppDir/

# build+install python
# TODO: check http://www.egenix.com/products/python/PyRun/ as an alternative!
RUN curl -o Python-2.7.12.tar.xz https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tar.xz && \
    tar xf Python-2.7.12.tar.xz && \
    cd Python-2.7.12 &&\
    ./configure --prefix=/raiden.AppDir/usr && \
    make && \
    make install && \
    cd .. && \
    rm -r Python-2.7.12*

# install 'pip'
RUN curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py && \
    usr/bin/python get-pip.py && \
    rm get-pip.py

# install node for webui
RUN curl -L -o /tmp/node.tar.gz https://nodejs.org/download/release/v8.2.1/node-v8.2.1-linux-x64.tar.gz && \
    cd /tmp && \
    tar xzvf node.tar.gz &&\
    mkdir /tmp/node_modules && \
    chmod -R a+rwX /tmp/node_modules

# install solc
RUN curl -L -o /usr/bin/solc https://github.com/ethereum/solidity/releases/download/v0.4.16/solc-static-linux && \
    chmod +x /usr/bin/solc

# use --build-arg RAIDENVERSION=v0.0.3 to build a specific (tagged) version
ARG REPO=raiden-network/raiden
ARG RAIDENVERSION=master

# This is a "hack" to automatically invalidate the cache in case there are new commits
ADD https://api.github.com/repos/${REPO}/commits/${RAIDENVERSION} /dev/null

# clone raiden
RUN mkdir -p /apps && \
    git clone https://github.com/${REPO}.git /apps/raiden

WORKDIR /apps/raiden

# install requirements (replacing all --editable requirements)
RUN git checkout $RAIDENVERSION && \
    sed -s 's/^-e //' requirements.txt > _requirements.txt && \
    /raiden.AppDir/usr/bin/pip install -r _requirements.txt

# build & install raiden with contracts, webui and smoketest
RUN echo "recursive-include raiden/ui/web/dist *" >> MANIFEST.in && \
    USER=root \
    NPM_CONFIG_PREFIX=/tmp/node_modules \
    NODE_PATH=/tmp/node_modules \
    PATH=/tmp/node-v8.2.1-linux-x64/bin:/raiden.AppDir/usr/bin:$PATH \
    /usr/bin/env python setup.py compile_contracts compile_webui build install && \
    find /raiden.AppDir/ -iname '*.pyo' -exec rm {} \; && \
    rm /raiden.AppDir/usr/lib/libpython*.a

WORKDIR /

# add .desktop file
ADD raiden.desktop /raiden.AppDir/raiden.desktop
RUN cd /apps/raiden && \
    VERSIONSTRING=$(/raiden.AppDir/usr/bin/raiden version --short) && \
    sed -s -i "s/XXVERSIONXX/$VERSIONSTRING/" /raiden.AppDir/raiden.desktop
# add icon
ADD raiden.svg /raiden.AppDir/raiden.svg

RUN curl -L -o functions.sh "https://github.com/probonopd/AppImages/raw/master/functions.sh"

# use AppImageKit 'functions.sh' to setup lib
RUN bash -c 'APP=Raiden LOWERAPP=raiden ARCH=x86_64 \
    PATH=/raiden.AppDir/usr/bin:$PATH PYTHONHOME=/raiden.AppDir/usr \
    source functions.sh && \
    cd /raiden.AppDir && \
    get_apprun && \
    ( copy_deps ; copy_deps ; copy_deps ) && \
    delete_blacklisted && \
    move_lib'

# fix python shebangs to point to '#!/usr/bin/env python'
RUN sed -i -s '1 s/^\#\!.*python\(.*\)/#!\/usr\/bin\/env python\1/' /raiden.AppDir/usr/bin/*

# we need python for functions.sh to work properly :o
RUN apt-get -y install python

# how to build AppImage
RUN echo "\n\nRun these commands to generate the AppImage:\n\tdocker run --name bundler --privileged -e ARCH=x86_64 -e APP=raiden -e LOWERAPP=raiden --workdir / --entrypoint /bin/bash raidenbundler -c 'source functions.sh && generate_appimage'\ndocker cp bundler:/out/raiden-.glibcPRIVATE-x86_64.AppImage dist/raiden--x86_64.AppImage\n\tdocker rm bundler\n\n"
