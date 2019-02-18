FROM python:3.7

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX

# install dependencies
RUN apt-get update
RUN apt-get install -y git-core wget xz-utils libgmp-dev

RUN wget -nv -O /usr/bin/solc ${SOLC_URL_LINUX} && \
    chmod +x /usr/bin/solc
RUN wget -nv -O /tmp/geth.tar.gz ${GETH_URL_LINUX} && \
    cd /tmp && \
    tar xf geth.tar.gz && \
    mv geth-linux-amd64-*/geth /usr/bin/geth && \
    rm geth.tar.gz


ADD requirements*.txt /tmp/
ADD constraints.txt /tmp/
WORKDIR /tmp

RUN pip install -U 'pip<19.0.0' setuptools setuptools_scm
RUN pip install -r requirements.txt -c constraints.txt
RUN pip install pyinstaller

ADD . /raiden

WORKDIR /raiden
RUN git fetch --tags | true


# build contracts and web_ui
RUN python setup.py build

# install raiden
RUN pip install -c constraints.txt .


ARG ARCHIVE_TAG
ARG ARCHITECTURE_TAG

# build pyinstaller package
RUN pyinstaller --noconfirm --clean raiden.spec

# pack result to have a unique name to get it out of the container later
RUN export FILE_TAG=${ARCHIVE_TAG:-v$(python setup.py --version)} && \
    cd dist && \
    tar -cvzf ./raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar.gz raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG} && \
    mv raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar.gz ..
