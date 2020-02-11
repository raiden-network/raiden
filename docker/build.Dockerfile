FROM python:3.7-stretch

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX

# install dependencies
RUN apt-get update
RUN apt-get install -y git-core wget xz-utils build-essential automake pkg-config libtool libffi-dev python3-dev libgmp-dev

RUN wget -nv -O /usr/bin/solc ${SOLC_URL_LINUX} && \
    chmod +x /usr/bin/solc
RUN wget -nv -O /tmp/geth.tar.gz ${GETH_URL_LINUX} && \
    cd /tmp && \
    tar xf geth.tar.gz && \
    mv geth-linux-amd64-*/geth /usr/bin/geth && \
    rm geth.tar.gz


RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

ADD requirements/requirements.txt /tmp/
WORKDIR /tmp


RUN pip install -U pip setuptools pip-tools
RUN pip-sync requirements.txt

ADD . /raiden

WORKDIR /raiden
RUN git fetch --tags || true

# install raiden
RUN make install && pip install pyinstaller

ARG ARCHIVE_TAG
ARG ARCHITECTURE_TAG

# build pyinstaller package
RUN pyinstaller --noconfirm --clean raiden.spec

# pack result to have a unique name to get it out of the container later
RUN export FILE_TAG=${ARCHIVE_TAG:-v$(python setup.py --version)} && \
    cd dist && \
    tar -cvzf ./raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar.gz raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG} && \
    mv raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar.gz ..
