import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from random import randint
from typing import Dict, List
from urllib.parse import parse_qs, urlparse

from Block import Block, build_candidate_block, mine_block
from Ecc import N, PrivateKey

BLOCKCHAIN: List[Block] = []
BALANCES: Dict[str, int] = {}

CHAIN_FILE = Path("genesis_block.bin")
BALANCES_FILE = Path("balances.json")


def _load_blockchain_from_disk():
    if not CHAIN_FILE.exists():
        return
    try:
        data = CHAIN_FILE.read_bytes()
    except OSError as err:
        print(f"Warning: unable to read {CHAIN_FILE}: {err}")
        return
    usable_length = len(data) - (len(data) % 80)
    if usable_length != len(data):
        print(
            f"Warning: ignoring {len(data) - usable_length} trailing bytes in {CHAIN_FILE}"
        )
    for offset in range(0, usable_length, 80):
        chunk = data[offset : offset + 80]
        block = Block.parse(BytesIO(chunk))
        BLOCKCHAIN.append(block)
    print(f"Loaded {len(BLOCKCHAIN)} block(s) from {CHAIN_FILE}")


def _load_balances_from_disk():
    if not BALANCES_FILE.exists():
        return
    try:
        payload = json.loads(BALANCES_FILE.read_text())
    except (OSError, json.JSONDecodeError) as err:
        print(f"Warning: unable to read {BALANCES_FILE}: {err}")
        return
    if not isinstance(payload, dict):
        print(f"Warning: invalid balances data in {BALANCES_FILE}")
        return
    for addr, amount in payload.items():
        try:
            BALANCES[addr] = int(amount)
        except (TypeError, ValueError):
            print(f"Warning: skipping invalid balance entry for {addr!r}")
    if BALANCES:
        print(f"Loaded {len(BALANCES)} balance(s) from {BALANCES_FILE}")


def _persist_balances():
    try:
        BALANCES_FILE.write_text(json.dumps(BALANCES, separators=(",", ":")))
    except OSError as err:
        print(f"Warning: unable to write {BALANCES_FILE}: {err}")


_load_blockchain_from_disk()
_load_balances_from_disk()


HOST = "127.0.0.1"
PORT = 8765


class AddressHandler(BaseHTTPRequestHandler):
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/balance":
            self._handle_balance(parsed)
            return
        self._send_json({"error": "Not found"}, status=404)

    def do_POST(self):
        if self.path == "/create-address":
            self._handle_create_address()
            return
        if self.path == "/mine":
            self._handle_mine()
            return

        self._send_json({"error": "Not found"}, status=404)

    def log_message(self, format, *args):
        return

    def _handle_create_address(self):
        secret = randint(1, N - 1)
        priv = PrivateKey(secret)
        address = priv.point.address(compressed=True, testnet=True)
        self._send_json({"address": address, "secret_hex": priv.hex()})

    def _handle_balance(self, parsed):
        query = parse_qs(parsed.query)
        address = query.get("address", [""])[0].strip()
        if not address:
            self._send_json(
                {"error": "address query parameter is required"}, status=400
            )
            return
        balance_sats = BALANCES.get(address, 0)
        balance_btc = balance_sats / 100_000_000
        self._send_json(
            {
                "address": address,
                "balance_sats": balance_sats,
                "balance_btc": balance_btc,
            }
        )

    def _handle_mine(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            self._send_json({"error": "Invalid Content-Length"}, status=411)
            return

        raw_body = self.rfile.read(content_length) if content_length > 0 else b"{}"
        try:
            payload = json.loads(raw_body.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            self._send_json({"error": "Invalid JSON body"}, status=400)
            return

        address = payload.get("address")
        if not address:
            self._send_json({"error": "address is required"}, status=400)
            return

        message = payload.get("message", "")
        start_nonce = int(payload.get("start_nonce", 0))
        max_nonce = int(payload.get("max_nonce", 0xFFFFFFFF))

        height = len(BLOCKCHAIN)
        prev_block = BLOCKCHAIN[-1].hash()[::-1] if BLOCKCHAIN else b"\x00" * 32

        block, coinbase_tx = build_candidate_block(
            height, prev_block, address, message=message
        )

        mined_block = mine_block(block, start_nonce=start_nonce, max_nonce=max_nonce)
        if mined_block is None:
            self._send_json({"error": "No valid nonce found in range"}, status=503)
            return

        BLOCKCHAIN.append(mined_block)
        with open("genesis_block.bin", "ab") as f:
            f.write(mined_block.serialize())
        block_hash = mined_block.hash().hex()

        result = {
            "height": height,
            "hash": block_hash,
            "prev_block": mined_block.prev_block.hex(),
            "merkle_root": mined_block.merkle_root_bytes[::-1].hex(),
            "nonce": int.from_bytes(mined_block.nonce, "little"),
            "timestamp": mined_block.timestamp,
            "bits": mined_block.bits.hex(),
            "coinbase_txid": coinbase_tx.id(),
            "block_hex": mined_block.serialize().hex(),
        }
        payout = sum(tx_out.amount for tx_out in coinbase_tx.tx_outs)
        BALANCES[address] = BALANCES.get(address, 0) + payout
        _persist_balances()
        self._send_json(result, status=201)

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    HTTPServer((HOST, PORT), AddressHandler).serve_forever()


# git remote add origin https://github.com/SunnyFoundation/btc_from_scratch.git


# mkaBghpnXRyKQWD47d1RCz2rx3b2gbSQZT
