FROM python:3.9-buster

# install dependencies
RUN apt-get update
RUN apt-get install -y git-core wget xz-utils build-essential \
    automake pkg-config libtool libffi-dev python3-dev libgmp-dev \
    libavdevice-dev libavfilter-dev libopus-dev libvpx-dev pkg-config \
    libsrtp2-dev

RUN python3 -m venv /venv
ENV PATH="/venv/bin:$PATH"

ADD requirements/requirements.txt /tmp/
WORKDIR /tmp


RUN pip install -U pip setuptools pip-tools wheel
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
    tar -cvf ./raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG} && \
    mv raiden-${FILE_TAG}-linux-${ARCHITECTURE_TAG}.tar ..
