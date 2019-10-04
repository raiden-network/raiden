#!/bin/env python
import json
import sys

for line in open(sys.argv[1]):
    data = json.loads(line)

    timestamp = data["timestamp"].split()[-1]
    if "state_changes" in data:
        state_changes = [sc["_type"].split(".")[-1] for sc in data["state_changes"]]
        print(f"> {timestamp}: {', '.join(state_changes)}")

    if "raiden_events" in data:
        events = [ev["_type"].split(".")[-1] for ev in data["raiden_events"]]
        print(f"< {timestamp}: {', '.join(events)}")
