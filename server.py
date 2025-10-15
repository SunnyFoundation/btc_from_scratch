import json
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from random import randint
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from Block import Block, build_candidate_block, mine_block
from Ecc import N, PrivateKey
from Script import p2pkh_script
from Tx import Tx, TxIn, TxOut
from helper import BASE58_ALPHABET, decode_base58, encode_base58_checksum, hash256

BLOCKCHAIN: List[Block] = []
BALANCES: Dict[str, int] = {}
UTXO_SET: Dict[str, Dict[str, int]] = {}

CHAIN_FILE = Path("genesis_block.bin")
BALANCES_FILE = Path("balances.json")
UTXO_FILE = Path("utxos.json")


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


def _normalize_utxo_identifier(
    utxo_id: str, txid: Optional[str], vout: Optional[int]
) -> Tuple[Optional[str], Optional[int]]:
    txid_candidate = txid if isinstance(txid, str) else None
    if txid_candidate:
        try:
            _ = bytes.fromhex(txid_candidate)
        except ValueError:
            txid_candidate = None
        else:
            if len(txid_candidate) != 64:
                txid_candidate = None

    vout_candidate = vout if isinstance(vout, int) and vout >= 0 else None

    if (txid_candidate is None or vout_candidate is None) and isinstance(utxo_id, str):
        if ":" in utxo_id:
            left, right = utxo_id.rsplit(":", 1)
            if txid_candidate is None:
                try:
                    _ = bytes.fromhex(left)
                except ValueError:
                    txid_candidate = None
                else:
                    if len(left) == 64:
                        txid_candidate = left
            if vout_candidate is None:
                try:
                    vout_candidate = int(right)
                except ValueError:
                    vout_candidate = None

    if txid_candidate is None:
        txid_candidate = hash256(str(utxo_id).encode("utf-8")).hex()
    if vout_candidate is None:
        vout_candidate = 0
    return txid_candidate, vout_candidate


def _load_utxos_from_disk():
    if not UTXO_FILE.exists():
        return
    try:
        payload = json.loads(UTXO_FILE.read_text())
    except (OSError, json.JSONDecodeError) as err:
        print(f"Warning: unable to read {UTXO_FILE}: {err}")
        return
    if not isinstance(payload, dict):
        print(f"Warning: invalid utxo data in {UTXO_FILE}")
        return
    UTXO_SET.clear()
    for orig_utxo_id, entry in payload.items():
        address = entry.get("address")
        amount = entry.get("amount_sats")
        txid = entry.get("txid")
        vout = entry.get("vout")
        if not isinstance(address, str):
            print(f"Warning: skipping UTXO {orig_utxo_id!r} due to invalid address")
            continue
        try:
            amount_int = int(amount)
        except (TypeError, ValueError):
            print(f"Warning: skipping UTXO {orig_utxo_id!r} due to invalid amount")
            continue
        if amount_int <= 0:
            continue

        txid_str, vout_int = _normalize_utxo_identifier(orig_utxo_id, txid, vout)
        if txid_str is None:
            print(f"Warning: skipping UTXO {orig_utxo_id!r} due to invalid txid/vout")
            continue

        utxo_key = f"{txid_str}:{vout_int}"
        UTXO_SET[utxo_key] = {
            "address": address,
            "amount_sats": amount_int,
            "txid": txid_str,
            "vout": vout_int,
        }
    if UTXO_SET:
        print(f"Loaded {len(UTXO_SET)} UTXO(s) from {UTXO_FILE}")


def _persist_utxos():
    try:
        data = {}
        for utxo_id, utxo in UTXO_SET.items():
            txid = utxo.get("txid")
            vout = utxo.get("vout")
            if not isinstance(txid, str) or len(txid) != 64 or not isinstance(vout, int):
                txid, vout = _normalize_utxo_identifier(utxo_id, txid, vout)
            key = f"{txid}:{vout}"
            data[key] = {
                "address": utxo["address"],
                "amount_sats": utxo["amount_sats"],
                "txid": txid,
                "vout": vout,
            }
        UTXO_FILE.write_text(json.dumps(data, separators=(",", ":")))
    except OSError as err:
        print(f"Warning: unable to write {UTXO_FILE}: {err}")


def _recalculate_balances():
    BALANCES.clear()
    for utxo in UTXO_SET.values():
        addr = utxo["address"]
        BALANCES[addr] = BALANCES.get(addr, 0) + utxo["amount_sats"]


def _bootstrap_utxos_from_balances():
    if UTXO_SET or not BALANCES:
        return
    print("Bootstrapping UTXO set from legacy balances.json data")
    for index, (addr, amount) in enumerate(BALANCES.items()):
        if amount <= 0:
            continue
        seed = f"legacy-{index}-{addr}".encode("utf-8")
        txid = hash256(seed).hex()
        vout = 0
        utxo_key = f"{txid}:{vout}"
        UTXO_SET[utxo_key] = {
            "address": addr,
            "amount_sats": amount,
            "txid": txid,
            "vout": vout,
        }
    _persist_utxos()


def _compute_balance(address: str) -> int:
    return sum(
        utxo["amount_sats"]
        for utxo in UTXO_SET.values()
        if utxo["address"] == address
    )


def _select_utxos(address: str, target_amount: int) -> Tuple[List[Tuple[str, Dict[str, int]]], int]:
    gathered: List[Tuple[str, Dict[str, int]]] = []
    total = 0
    for utxo_id, utxo in UTXO_SET.items():
        if utxo["address"] != address:
            continue
        gathered.append((utxo_id, utxo))
        total += utxo["amount_sats"]
        if total >= target_amount:
            break
    return gathered, total


def _decode_base58_with_checksum(s: str) -> bytes:
    num = 0
    for c in s:
        if c not in BASE58_ALPHABET:
            raise ValueError(f"invalid base58 character: {c}")
        num = num * 58 + BASE58_ALPHABET.index(c)
    combined = num.to_bytes((num.bit_length() + 7) // 8, "big")
    pad = 0
    for char in s:
        if char == "1":
            pad += 1
        else:
            break
    combined = b"\x00" * pad + combined
    if len(combined) < 5:
        raise ValueError("invalid base58 data")
    payload, checksum = combined[:-4], combined[-4:]
    if hash256(payload)[:4] != checksum:
        raise ValueError("invalid checksum")
    return payload


def _wif_to_private_key(wif: str) -> Tuple[PrivateKey, bool, bool]:
    payload = _decode_base58_with_checksum(wif)
    prefix = payload[0]
    if prefix not in (0x80, 0xEF):
        raise ValueError("unsupported WIF prefix")
    compressed = False
    if len(payload) == 34 and payload[-1] == 0x01:
        compressed = True
        secret_bytes = payload[1:-1]
    elif len(payload) == 33:
        secret_bytes = payload[1:]
    else:
        raise ValueError("unexpected WIF payload length")
    secret = int.from_bytes(secret_bytes, "big")
    if not (1 <= secret < N):
        raise ValueError("invalid secret in WIF")
    priv = PrivateKey(secret)
    testnet = prefix == 0xEF
    return priv, compressed, testnet


_load_blockchain_from_disk()
_load_balances_from_disk()
_load_utxos_from_disk()
_bootstrap_utxos_from_balances()
_recalculate_balances()


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
        if self.path == "/send":
            self._handle_send()
            return

        self._send_json({"error": "Not found"}, status=404)

    def log_message(self, format, *args):
        return

    def _handle_create_address(self):
        secret = randint(1, N - 1)
        priv = PrivateKey(secret)
        address = priv.point.address(compressed=True, testnet=True)
        wif = self._private_key_to_wif(priv, compressed=True, testnet=True)
        self._send_json({"address": address, "secret_hex": priv.hex(), "wif": wif})

    def _handle_balance(self, parsed):
        query = parse_qs(parsed.query)
        address = query.get("address", [""])[0].strip()
        if not address:
            self._send_json(
                {"error": "address query parameter is required"}, status=400
            )
            return
        balance_sats = BALANCES.get(address, 0)
        if balance_sats == 0:
            balance_sats = _compute_balance(address)
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
        coinbase_txid = coinbase_tx.id()
        coinbase_utxo_id = f"{coinbase_txid}:0"
        UTXO_SET[coinbase_utxo_id] = {
            "address": address,
            "amount_sats": payout,
            "txid": coinbase_txid,
            "vout": 0,
        }
        _persist_utxos()
        _recalculate_balances()
        _persist_balances()
        self._send_json(result, status=201)

    def _handle_send(self):
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

        from_address = (payload.get("from_address") or "").strip()
        to_address = (payload.get("to_address") or "").strip()
        amount_raw = payload.get("amount_sats")
        wif = (payload.get("wif") or "").strip()

        if not from_address or not to_address:
            self._send_json(
                {"error": "from_address and to_address are required"}, status=400
            )
            return

        try:
            amount_sats = int(amount_raw)
        except (TypeError, ValueError):
            self._send_json({"error": "amount_sats must be an integer"}, status=400)
            return
        if amount_sats <= 0:
            self._send_json({"error": "amount_sats must be positive"}, status=400)
            return

        if wif:
            try:
                priv, compressed, testnet = _wif_to_private_key(wif)
            except ValueError as exc:
                self._send_json({"error": f"Invalid WIF: {exc}"}, status=400)
                return
            derived_address = priv.point.address(compressed=compressed, testnet=testnet)
            if derived_address != from_address:
                self._send_json(
                    {"error": "WIF does not correspond to from_address"}, status=400
                )
                return

        selected_utxos, total_available = _select_utxos(from_address, amount_sats)
        if total_available < amount_sats:
            self._send_json({"error": "Insufficient balance"}, status=400)
            return

        change_sats = total_available - amount_sats
        tx_ins: List[TxIn] = []
        for utxo_id, utxo in selected_utxos:
            txid_str, vout_index = _normalize_utxo_identifier(
                utxo_id, utxo.get("txid"), utxo.get("vout")
            )
            if txid_str is None or vout_index is None:
                self._send_json(
                    {
                        "error": f"Unable to use UTXO {utxo_id}: missing txid or index"
                    },
                    status=500,
                )
                return
            try:
                prev_tx_bytes = bytes.fromhex(txid_str)
            except ValueError:
                self._send_json(
                    {"error": f"Unable to decode txid for UTXO {utxo_id}"},
                    status=500,
                )
                return
            tx_ins.append(TxIn(prev_tx=prev_tx_bytes, prev_index=vout_index))

        tx_outs: List[TxOut] = []
        try:
            to_h160 = decode_base58(to_address)
        except ValueError:
            self._send_json({"error": "Invalid destination address"}, status=400)
            return
        tx_outs.append(TxOut(amount_sats, p2pkh_script(to_h160)))

        outputs_for_utxo = [(to_address, amount_sats)]

        if change_sats > 0:
            try:
                change_h160 = decode_base58(from_address)
            except ValueError:
                self._send_json({"error": "Invalid change address"}, status=400)
                return
            tx_outs.append(TxOut(change_sats, p2pkh_script(change_h160)))
            outputs_for_utxo.append((from_address, change_sats))

        tx = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0, testnet=True)
        txid = tx.id()

        for utxo_id, _ in selected_utxos:
            UTXO_SET.pop(utxo_id, None)

        for output_index, (addr, amt) in enumerate(outputs_for_utxo):
            utxo_key = f"{txid}:{output_index}"
            UTXO_SET[utxo_key] = {
                "address": addr,
                "amount_sats": amt,
                "txid": txid,
                "vout": output_index,
            }

        raw_tx_hex = tx.serialize().hex()
        _persist_utxos()
        _recalculate_balances()
        _persist_balances()

        self._send_json(
            {
                "txid": txid,
                "from_address": from_address,
                "to_address": to_address,
                "amount_sats": amount_sats,
                "fee_sats": 0,
                "raw_tx_hex": raw_tx_hex,
                "note": "Simulated transaction recorded only in local ledger",
            },
            status=201,
        )

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def _private_key_to_wif(priv, *, compressed=True, testnet=True):
        prefix = b"\xEF" if testnet else b"\x80"
        suffix = b"\x01" if compressed else b""
        secret_bytes = priv.secret.to_bytes(32, "big")
        return encode_base58_checksum(prefix + secret_bytes + suffix)


if __name__ == "__main__":
    HTTPServer((HOST, PORT), AddressHandler).serve_forever()


# git remote add origin https://github.com/SunnyFoundation/btc_from_scratch.git


# mkaBghpnXRyKQWD47d1RCz2rx3b2gbSQZT
