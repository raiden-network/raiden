#!/usr/bin/env bash

for server in "$@"; do
    ssh "$server" 'tar -cf - $(find /data -mtime -1) | gzip -c' | tar xzf -
done
