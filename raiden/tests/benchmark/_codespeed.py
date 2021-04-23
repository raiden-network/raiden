import json
import socket
import urllib.error
import urllib.parse
import urllib.request


def post_result(codespeed_url, commit_id, branch, bench_name, value):
    hostname = socket.gethostname()
    data = [
        {
            "commitid": commit_id,
            "project": "raiden",
            "branch": branch,
            "executable": "raiden",
            "benchmark": bench_name,
            "environment": hostname,
            "result_value": value,
        }
    ]

    data_ = {"json": json.dumps(data)}
    request_data = urllib.parse.urlencode(data_).encode("utf-8")
    url = codespeed_url + "/result/add/json/"
    try:
        with urllib.request.urlopen(url, request_data):
            pass
    except urllib.error.HTTPError as e:
        print(str(e))
        print(e.read())
