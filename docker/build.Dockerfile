# backward compatibility:
FROM ubuntu:12.04.5

# install build dependencies
RUN apt-get update && \
 apt-get install -y curl wget automake build-essential git-core libffi-dev \ 
 libgmp-dev libssl-dev libtool pkg-config fuse

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

RUN curl -L -o /usr/bin/solc https://github.com/brainbot-com/solidity-static/releases/download/v0.4.9/solc && \
    chmod +x /usr/bin/solc

# use --build-arg RAIDEN_VERSION=v0.0.3 to build a specific (tagged) version
ARG RAIDEN_VERSION

# install raiden (replacing all --editable requirements)
RUN mkdir -p /apps && \
    git clone https://github.com/raiden-network/raiden.git /apps/raiden && \
    cd /apps/raiden  && \ 
    git checkout $RAIDEN_VERSION && \
    sed -s 's/^-e //' requirements.txt > _requirements.txt && \
    /raiden.AppDir/usr/bin/pip install -r _requirements.txt && \
    PATH=/raiden.AppDir/usr/bin:$PATH /usr/bin/env python setup.py compile_contracts install && \
    find /raiden.AppDir/ -iname '*.pyo' -exec rm {} \; && \
    rm /raiden.AppDir/usr/lib/libpython*.a

WORKDIR /

# add .desktop file
ADD raiden.desktop /raiden.AppDir/raiden.desktop
RUN cd /apps/raiden && \
    VERSIONSTRING=${RAIDEN_VERSION:-"git-"$(git rev-parse HEAD)} && \
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
RUN echo "\n\nRun these commands to generate the AppImage:\n\tdocker run --name bundler --privileged -e ARCH=x86_64 -e APP=raiden -e LOWERAPP=raiden --workdir / --entrypoint /bin/bash raidenbundler -c 'source functions.sh && generate_appimage'\ndocker cp bundler:raiden--x86_64.AppImage .\n\tdocker rm bundler\n\n"
