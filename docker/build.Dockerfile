FROM python:3.6

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX

# install dependencies
RUN apt-get update --fix-missing
RUN apt-get install -y git-core wget xz-utils

RUN wget -nv -O /usr/bin/solc ${SOLC_URL_LINUX} && \
    chmod +x /usr/bin/solc
RUN wget -nv -O /tmp/geth.tar.gz ${GETH_URL_LINUX} && \
    cd /tmp && \
    tar xf geth.tar.gz && \
    mv geth-linux-amd64-*/geth /usr/bin/geth && \
    rm geth.tar.gz

ADD . /raiden

WORKDIR /raiden
RUN git fetch --tags | true
RUN pip install -U pip setuptools
RUN pip install -r requirements.txt -c constraints.txt

# build contracts and web_ui
RUN python setup.py build

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
