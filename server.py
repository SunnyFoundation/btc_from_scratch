from http.server import BaseHTTPRequestHandler, HTTPServer
from random import randint
import json

from Ecc import PrivateKey, N


HOST = "127.0.0.1"
PORT = 8765


class AddressHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/create-address":
            self.send_error(404, "Not found")
            return

        secret = randint(1, N - 1)
        priv = PrivateKey(secret)
        address = priv.point.address(compressed=True, testnet=True)

        payload = json.dumps({"address": address, "secret_hex": priv.hex()}).encode(
            "utf-8"
        )

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    HTTPServer((HOST, PORT), AddressHandler).serve_forever()


# git remote add origin https://github.com/SunnyFoundation/btc_from_scratch.git
