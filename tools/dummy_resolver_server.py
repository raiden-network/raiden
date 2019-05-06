import json
import logging
from http.server import BaseHTTPRequestHandler, HTTPServer

from eth_utils import to_bytes, to_hex

from raiden.utils import sha3

# The code below simulates XUD resolver functionality.
# It should only be used for testing and should not be used in
# run time or production.


def resolve(request):

    preimage = None

    x_secret = "0x2ff886d47b156de00d4cad5d8c332706692b5b572adfe35e6d2f65e92906806e"
    x_secret_hash = to_hex(sha3(to_bytes(hexstr=x_secret)))

    if request["secret_hash"] == x_secret_hash:
        preimage = {"secret": x_secret}

    return preimage


def serve():
    class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            try:
                content_len = int(self.headers.get("Content-Length"))
                body = self.rfile.read(content_len)

                preimage = resolve(json.loads(body.decode("utf8")))
                if preimage is None:
                    self.send_response(404)
                    self.end_headers()
                else:
                    response = to_bytes(text=json.dumps(preimage))
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(response)
            except BaseException:
                self.send_response(400)
                self.end_headers()

    httpd = HTTPServer(("localhost", 8000), SimpleHTTPRequestHandler)
    httpd.serve_forever()


if __name__ == "__main__":
    logging.basicConfig()
    serve()
