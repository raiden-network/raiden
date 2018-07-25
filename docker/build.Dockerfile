FROM python:3.6

# these are defined in .travis.yml and passed here in the makefile
ARG SOLC_URL_LINUX
ARG GETH_URL_LINUX

# install dependencies
RUN apt-get update
RUN apt-get install -y git-core wget

RUN wget -O /usr/bin/solc ${SOLC_URL_LINUX} && chmod +x /usr/bin/solc
RUN wget -O /tmp/geth.tar.gz ${GETH_URL_LINUX} && cd /tmp && tar xzvf geth.tar.gz && mv geth-linux-amd64-1.8.0-5f540757/geth /usr/bin/geth && rm geth.tar.gz
RUN wget -O /tmp/node.tar.gz https://nodejs.org/download/release/v8.11.3/node-v8.11.3-linux-x64.tar.gz && cd /tmp && tar xzvf node.tar.gz && mkdir /tmp/node_modules && chmod -R a+rwX /tmp/node_modules && rm node.tar.gz


# use --build-arg RAIDENVERSION=v0.0.3 to build a specific (tagged) version
ARG REPO=raiden-network/raiden
ARG RAIDENVERSION=master

# This is a "hack" to automatically invalidate the cache in case there are new commits
ADD https://api.github.com/repos/${REPO}/commits/${RAIDENVERSION} /dev/null

# clone raiden repo + install dependencies
RUN git clone -b ${RAIDENVERSION} https://github.com/${REPO}
RUN git fetch --tags
WORKDIR /raiden
RUN pip install -r requirements.txt

# build contracts and web_ui
RUN python setup.py build
RUN USER=root NPM_CONFIG_PREFIX=/tmp/node_modules NODE_PATH=/tmp/node_modules PATH=/tmp/node-v8.2.1-linux-x64/bin:$PATH python setup.py compile_webui

# install raiden and pyinstaller
RUN pip install .
RUN pip install pyinstaller

# build pyinstaller package
RUN pyinstaller --noconfirm --clean raiden.spec

# pack result to have a unique name to get it out of the container later
RUN cd dist && tar -cvzf raiden-${RAIDENVERSION}-linux.tar.gz raiden* && mv raiden-${RAIDENVERSION}-linux.tar.gz ..
