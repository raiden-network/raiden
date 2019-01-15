
# This will build the latest master
#
# we use an intermediate image to build this image. it will make the resulting
# image a bit smaller.
#
# you can build the image with:
#
#   docker build . -t raiden

FROM python:3 as builder

# use --build-arg RAIDENVERSION=v0.0.3 to build a specific (tagged) version
ARG REPO=raiden-network/raiden
ARG RAIDENVERSION=master

# This is a "hack" to automatically invalidate the cache in case there are new commits
ADD https://api.github.com/repos/${REPO}/commits/${RAIDENVERSION} /dev/null

# clone raiden repo + install dependencies
RUN git clone -b ${RAIDENVERSION} https://github.com/${REPO} /app/raiden

RUN python3 -m venv /opt/venv

RUN /opt/venv/bin/pip3 install -c /app/raiden/constraints.txt -r /app/raiden/requirements.txt /app/raiden


FROM python:3-slim as runner

COPY --from=builder /opt/venv /opt/venv

EXPOSE 5001

ENTRYPOINT ["/opt/venv/bin/python3", "-m", "raiden"]
