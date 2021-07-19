import json
import os
import warnings

import requests

try:
    _CODESPEED_USER = os.environ["CODESPEED_USER"]

    _CODESPEED_PASSWORD = os.environ["CODESPEED_PASSWORD"]

    _BENCHMARK_HOST = os.environ["BENCHMARK_HOST"]
except KeyError:
    warnings.warn(
        "Codespeed environment variables not available, posting results would fail.",
        RuntimeWarning,
    )


def post_result(codespeed_url, commit_id, branch, bench_name, value):
    data = [
        {
            "commitid": commit_id,
            "project": "raiden",
            "branch": branch,
            "executable": "raiden",
            "benchmark": bench_name,
            "environment": _BENCHMARK_HOST,
            "result_value": value,
        }
    ]

    data_ = {"json": json.dumps(data)}
    url = codespeed_url + "/result/add/json/"
    resp = requests.post(url, data=data_, auth=(_CODESPEED_USER, _CODESPEED_PASSWORD))
    resp.raise_for_status()
