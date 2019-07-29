
# This will build the latest master
#
# we use an intermediate image to build this image. it will make the resulting
# image a bit smaller.
#
# you can build the image with:
#
#   docker build . -t raiden

FROM python:3.7 as builder

# use --build-arg RAIDENVERSION=v0.0.3 to build a specific (tagged) version
ARG REPO=raiden-network/raiden
ARG RAIDENVERSION=develop

# This is a "hack" to automatically invalidate the cache in case there are new commits
ADD https://api.github.com/repos/${REPO}/commits/${RAIDENVERSION} /dev/null

# clone raiden repo + install dependencies
RUN git clone -b ${RAIDENVERSION} https://github.com/${REPO} /app/raiden

RUN python3 -m venv /opt/venv

ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /app/raiden

RUN make install


FROM python:3.7-slim as runner

COPY --from=builder /opt/venv /opt/venv

EXPOSE 5001

ENTRYPOINT ["/opt/venv/bin/python3", "-m", "raiden"]
