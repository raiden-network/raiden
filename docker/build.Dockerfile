FROM python:3.7

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX

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

ADD . /raiden

WORKDIR /raiden
RUN git fetch --tags | true
RUN pip install -U 'pip<19.0.0' setuptools setuptools_scm
RUN pip install -r requirements.txt -c constraints.txt

# install raiden and pyinstaller
RUN pip install -c constraints.txt .
RUN pip install pyinstaller

ARG ARCHIVE_TAG

# build pyinstaller package
RUN pyinstaller --noconfirm --clean raiden.spec

# pack result to have a unique name to get it out of the container later
RUN export FILE_TAG=${ARCHIVE_TAG:-v$(python setup.py --version)} && \
    cd dist && \
    tar -cvzf ./raiden-${FILE_TAG}-linux.tar.gz raiden-${FILE_TAG}-linux && \
    mv raiden-${FILE_TAG}-linux.tar.gz ..
