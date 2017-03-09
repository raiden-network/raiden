# backward compatibility:
FROM ubuntu:12.04.5

RUN apt-get update && \
 apt-get install -y curl wget automake build-essential git-core libffi-dev \ 
 libgmp-dev libssl-dev libtool pkg-config fuse

RUN bash -c 'mkdir -p /raiden.AppDir/usr/{local,bin,share,lib}/'

WORKDIR /raiden.AppDir/

RUN curl -o Python-2.7.12.tar.xz https://www.python.org/ftp/python/2.7.12/Python-2.7.12.tar.xz

RUN tar xf Python-2.7.12.tar.xz

RUN cd Python-2.7.12 &&\
    ./configure --prefix=/raiden.AppDir/usr && \
    make && \
    make install

RUN rm -r Python-2.7.12*

RUN curl -o get-pip.py https://bootstrap.pypa.io/get-pip.py && \
    usr/bin/python get-pip.py

RUN mkdir -p /apps && \
    git clone https://github.com/raiden-network/raiden.git /apps/raiden && \
    cd /apps/raiden  && \ 
    sed -s 's/^-e //' requirements.txt > _requirements.txt && \
    /raiden.AppDir/usr/bin/pip install -r _requirements.txt && \
    /raiden.AppDir/usr/bin/python setup.py install

RUN curl -L -o /raiden.AppDir/usr/bin/solc https://github.com/brainbot-com/solidity-static/releases/download/v0.4.9/solc && \
    chmod +x /raiden.AppDir/usr/bin/solc

WORKDIR /

# RUN curl -L -o /appimagetool https://github.com/probonopd/AppImageKit/releases/download/continuous/appimagetool-x86_64.AppImage && \
#     chmod +x /appimagetool && \
#     curl -L -o /raiden.AppDir/AppRun https://github.com/probonopd/AppImageKit/releases/download/continuous/AppRun-x86_64 && \
#     chmod +x /raiden.AppDir/AppRun

ADD raiden.desktop /raiden.AppDir/raiden.desktop
ADD raiden.svg /raiden.AppDir/raiden.svg
ADD apprun.sh /raiden.AppDir/usr/bin/apprun.sh
RUN chmod a+x /raiden.AppDir/usr/bin/apprun.sh

RUN mkdir -p /raiden.AppDir/usr/lib/x86_64-linux-gnu/ && \
    cp /lib/x86_64-linux-gnu/libssl.so.1.0.0 /raiden.AppDir/usr/lib/x86_64-linux-gnu/ && \
    cp /usr/lib/x86_64-linux-gnu/libgmp.so.10 /raiden.AppDir/usr/lib/x86_64-linux-gnu/ && \
    cp /lib/x86_64-linux-gnu/libcrypto.so.1.0.0 /raiden.AppDir/usr/lib/x86_64-linux-gnu/

# RUN cd /raiden.AppDir/usr/lib/python2.7/site-packages/ && \
#     for file in *.egg-link; do \
#     cp -rn $(cat $file); \
#     rm $file; \
#     done

# we need python for functions to work properly :o
RUN apt-get -y install python

RUN curl -L -o functions.sh "https://github.com/probonopd/AppImages/raw/master/functions.sh"

RUN bash -c 'APP=Raiden LOWERAPP=raiden ARCH=x86_64 source functions.sh && \
    cd /raiden.AppDir && \
    get_apprun && \
    copy_deps ; copy_deps ; copy_deps && \
    move_lib'

ADD raiden /raiden.AppDir/usr/bin/raiden
RUN chmod +x /raiden.AppDir/usr/bin/raiden

# RUN bash -c 'APP=Raiden LOWERAPP=raiden ARCH=x86_64 source functions.sh && \
#     ARCH=x86_64 generate_appimage'
# FIXME: dev dependency
# RUN apt-get -y install vim strace locate && \
#     updatedb
