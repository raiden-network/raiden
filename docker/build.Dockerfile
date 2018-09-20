FROM python:3.6

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX
ARG NODE_DOWNLOAD_URL=https://nodejs.org/dist/v10.9.0/node-v10.9.0-linux-x64.tar.xz

# install dependencies
RUN apt-get update
RUN apt-get install -y git-core wget xz-utils

RUN wget -nv -O /usr/bin/solc ${SOLC_URL_LINUX} && \
    chmod +x /usr/bin/solc
RUN wget -nv -O /tmp/geth.tar.gz ${GETH_URL_LINUX} && \
    cd /tmp && \
    tar xf geth.tar.gz && \
    mv geth-linux-amd64-*/geth /usr/bin/geth && \
    rm geth.tar.gz
RUN cd /tmp && \
    wget -nv ${NODE_DOWNLOAD_URL} && \
    mkdir node && \
    tar -xf node*.tar.* --strip 1 -C node && \
    mkdir /tmp/node_modules && \
    chmod -R a+rwX /tmp/node_modules && \
    rm node*.tar.*

ADD . /raiden

WORKDIR /raiden
RUN git fetch --tags
RUN pip install -U pip setuptools
RUN pip install -r requirements.txt -c constraints.txt

# build contracts and web_ui
RUN python setup.py build
RUN USER=root \
    NPM_CONFIG_PREFIX=/tmp/node_modules \
    NODE_PATH=/tmp/node_modules \
    PATH=/tmp/node/bin:$PATH \
    RAIDEN_NPM_MISSING_FATAL=1 \
    python setup.py compile_webui

# install raiden and pyinstaller
RUN pip install .
RUN pip install pyinstaller

# build pyinstaller package
RUN pyinstaller --noconfirm --clean raiden.spec

ARG ARCHIVE_TAG

# pack result to have a unique name to get it out of the container later
RUN cd dist && \
    tar -cvzf ./raiden-${ARCHIVE_TAG}-linux.tar.gz raiden* && \
    mv raiden-${ARCHIVE_TAG}-linux.tar.gz ..
