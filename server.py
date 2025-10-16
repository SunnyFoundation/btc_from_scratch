import json
import os
import secrets
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path
from random import randint
from typing import Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from Block import Block, build_candidate_block, mine_block
from Ecc import N, PrivateKey
from Script import Script, p2pkh_script
from Tx import Tx, TxIn, TxOut
from helper import (
    BASE58_ALPHABET,
    SIGHASH_ALL,
    decode_base58,
    encode_base58_checksum,
    hash256,
    merkle_root,
)
from p2p import DEFAULT_LISTEN_HOST, DEFAULT_P2P_PORT, PeerManager, _load_peer_list
import requests

BLOCKCHAIN: List[Block] = []
BALANCES: Dict[str, int] = {}
UTXO_SET: Dict[str, Dict[str, int]] = {}
MEMPOOL: Dict[str, Dict] = {}

CHAIN_FILE = Path("genesis_block.bin")
BALANCES_FILE = Path("balances.json")
UTXO_FILE = Path("utxos.json")

NODE_ID = os.environ.get("SUNNY_NODE_ID") or secrets.token_hex(8)
P2P_MANAGER: Optional[PeerManager] = None


def _load_blockchain_from_disk():
    BLOCKCHAIN.clear()
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
    BALANCES.clear()
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


def _apply_transaction(
    tx: Tx,
    script_pubkeys: List[Script],
    *,
    expect_signed: bool = True,
) -> Tuple[int, List[Tuple[str, int]]]:
    if expect_signed:
        for idx, script in enumerate(script_pubkeys):
            z = tx.sig_hash(idx)
            combined_script = tx.tx_ins[idx].script_sig + script
            if not combined_script.evaluate(z):
                raise ValueError("Signature verification failed")

    total_out = 0
    outputs_for_utxo: List[Tuple[str, int]] = []
    for tx_out in tx.tx_outs:
        try:
            cmds = tx_out.script_pubkey.cmds
        except AttributeError as exc:
            raise ValueError("Invalid TxOut script") from exc
        if len(cmds) != 5 or cmds[0] != 0x76 or cmds[1] != 0xA9:
            raise ValueError("Only p2pkh outputs supported")
        h160 = cmds[2]
        if not isinstance(h160, bytes):
            raise ValueError("Invalid script command in TxOut")
        address = encode_base58_checksum(b"\x6f" + h160)
        amount = tx_out.amount
        if not isinstance(amount, int) or amount <= 0:
            raise ValueError("Invalid TxOut amount")
        total_out += amount
        outputs_for_utxo.append((address, amount))
    return total_out, outputs_for_utxo


def _extract_input_scripts(tx: Tx) -> List[Script]:
    scripts: List[Script] = []
    for tx_in in tx.tx_ins:
        prev_txid = tx_in.prev_tx.hex()
        key = f"{prev_txid}:{tx_in.prev_index}"
        utxo = UTXO_SET.get(key)
        if utxo is None:
            raise ValueError(f"Unknown UTXO referenced: {key}")
        address = utxo.get("address")
        if not isinstance(address, str):
            raise ValueError(f"Stored UTXO missing address: {key}")
        try:
            h160 = decode_base58(address)
        except ValueError as exc:
            raise ValueError(f"Invalid address in UTXO {key}") from exc
        scripts.append(p2pkh_script(h160))
    return scripts


def _status_error(message: str, http_status: int):
    return "error", {"error": message}, http_status, None, None


def _accept_transaction(
    raw_tx_hex: str,
    *,
    origin: Optional[str] = None,
) -> Tuple[str, Dict, int, Optional[str], Optional[str]]:
    raw_tx_hex = (raw_tx_hex or "").strip()
    if not raw_tx_hex:
        return _status_error("raw_tx_hex is required", 400)
    try:
        tx_bytes = bytes.fromhex(raw_tx_hex)
    except ValueError:
        return _status_error("raw_tx_hex must be valid hex", 400)

    try:
        tx = Tx.parse(BytesIO(tx_bytes), testnet=True)
    except Exception as exc:  # noqa: BLE001
        return _status_error(f"Unable to parse transaction: {exc}", 400)

    txid = tx.id()
    if txid in MEMPOOL:
        payload = {"status": "duplicate", "txid": txid}
        return "duplicate", payload, 200, txid, raw_tx_hex

    try:
        script_pubkeys = _extract_input_scripts(tx)
    except ValueError as exc:
        message = str(exc)
        status_code = 404 if message.startswith("Unknown UTXO") else 400
        return _status_error(message, status_code)

    for idx, script in enumerate(script_pubkeys):
        tx.tx_ins[idx].script_pubkey = (  # type: ignore[attr-defined]
            lambda testnet=True, script=script: script
        )

    spent_outpoints = set()
    total_in = 0
    inputs_info = []
    for tx_in in tx.tx_ins:
        prev_txid = tx_in.prev_tx.hex()
        key = f"{prev_txid}:{tx_in.prev_index}"
        utxo = UTXO_SET.get(key)
        if utxo is None:
            return _status_error(f"Unknown UTXO referenced: {key}", 404)
        total_in += utxo["amount_sats"]
        inputs_info.append(
            {
                "txid": utxo.get("txid", prev_txid),
                "vout": utxo.get("vout", tx_in.prev_index),
                "amount_sats": utxo["amount_sats"],
                "address": utxo["address"],
            }
        )
        spent_outpoints.add(key)

    for existing in MEMPOOL.values():
        for entry in existing.get("inputs", []):
            if f"{entry['txid']}:{entry['vout']}" in spent_outpoints:
                return _status_error(
                    "Input already spent by mempool transaction", 409
                )

    try:
        total_out, outputs_for_utxo = _apply_transaction(
            tx, script_pubkeys, expect_signed=True
        )
    except ValueError as exc:
        return _status_error(str(exc), 400)

    fee = total_in - total_out
    if fee < 0:
        return _status_error("Transaction outputs exceed inputs", 400)

    MEMPOOL[txid] = {
        "tx_hex": raw_tx_hex,
        "inputs": inputs_info,
        "outputs": [
            {"address": addr, "amount_sats": amt} for addr, amt in outputs_for_utxo
        ],
        "fee_sats": fee,
        "received_at": time.time(),
        "origin": origin or NODE_ID,
    }

    payload = {
        "status": "accepted",
        "txid": txid,
        "fee_sats": fee,
        "mempool_size": len(MEMPOOL),
    }
    return "accepted", payload, 202, txid, raw_tx_hex


def _handle_incoming_tx_from_peer(raw_tx_hex: str, origin: Optional[str]) -> None:
    status, _, _, _, stored_hex = _accept_transaction(raw_tx_hex, origin=origin)
    if status != "accepted":
        return
    if P2P_MANAGER is not None:
        P2P_MANAGER.broadcast_tx(stored_hex or raw_tx_hex, origin=origin)


def _apply_confirmed_transaction(tx: Tx) -> None:
    txid = tx.id()
    for tx_in in tx.tx_ins:
        prev_txid = tx_in.prev_tx.hex()
        key = f"{prev_txid}:{tx_in.prev_index}"
        UTXO_SET.pop(key, None)
    for index, tx_out in enumerate(tx.tx_outs):
        try:
            cmds = tx_out.script_pubkey.cmds
        except AttributeError:
            continue
        if len(cmds) != 5 or cmds[0] != 0x76 or cmds[1] != 0xA9:
            continue
        h160 = cmds[2]
        if not isinstance(h160, bytes):
            continue
        address = encode_base58_checksum(b"\x6f" + h160)
        key = f"{txid}:{index}"
        UTXO_SET[key] = {
            "address": address,
            "amount_sats": tx_out.amount,
            "txid": txid,
            "vout": index,
        }


def _handle_incoming_block_from_peer(message: Dict, origin: Optional[str]) -> None:
    if not isinstance(message, dict):
        return
    block_hex = message.get("block_hex")
    coinbase_hex = message.get("coinbase_tx")
    tx_hexes = message.get("transactions") or []
    if not isinstance(block_hex, str) or not isinstance(coinbase_hex, str):
        return
    try:
        block_bytes = bytes.fromhex(block_hex)
        block = Block.parse(BytesIO(block_bytes))
    except Exception:
        return

    block_hash = block.hash().hex()
    if any(existing.hash().hex() == block_hash for existing in BLOCKCHAIN):
        return

    if BLOCKCHAIN:
        expected_prev = BLOCKCHAIN[-1].hash()[::-1]
        if block.prev_block != expected_prev:
            return
    else:
        if block.prev_block != b"\x00" * 32:
            return

    try:
        coinbase_tx = Tx.parse(BytesIO(bytes.fromhex(coinbase_hex)), testnet=True)
    except Exception:
        return

    transactions: List[Tx] = []
    spent_in_block = set()
    for tx_hex in tx_hexes:
        if not isinstance(tx_hex, str):
            return
        try:
            tx = Tx.parse(BytesIO(bytes.fromhex(tx_hex)), testnet=True)
        except Exception:
            return
        try:
            script_pubkeys = _extract_input_scripts(tx)
        except ValueError:
            return

        for idx, script in enumerate(script_pubkeys):
            tx.tx_ins[idx].script_pubkey = (  # type: ignore[attr-defined]
                lambda testnet=True, script=script: script
            )

        temp_spent = [f"{tx_in.prev_tx.hex()}:{tx_in.prev_index}" for tx_in in tx.tx_ins]
        if any(entry in spent_in_block for entry in temp_spent):
            return

        for idx, script in enumerate(script_pubkeys):
            z = tx.sig_hash(idx)
            combined = tx.tx_ins[idx].script_sig + script
            if not combined.evaluate(z):
                return

        spent_in_block.update(temp_spent)
        transactions.append(tx)

    all_txs = [coinbase_tx] + transactions
    tx_hashes_be = [bytes.fromhex(tx.id()) for tx in all_txs]
    if merkle_root(tx_hashes_be)[::-1] != block.merkle_root_bytes:
        return
    block.tx_hashes = [h[::-1] for h in tx_hashes_be]

    BLOCKCHAIN.append(block)
    with open("genesis_block.bin", "ab") as f:
        f.write(block.serialize())

    _apply_confirmed_transaction(coinbase_tx)
    for tx in transactions:
        _apply_confirmed_transaction(tx)
        MEMPOOL.pop(tx.id(), None)

    _persist_utxos()
    _recalculate_balances()
    _persist_balances()

    if P2P_MANAGER is not None:
        P2P_MANAGER.broadcast_block(message, origin=origin or NODE_ID)


def _apply_sync_snapshot(snapshot: Dict) -> bool:
    chain_hex = snapshot.get("chain_hex")
    utxos = snapshot.get("utxos")
    balances = snapshot.get("balances")
    if not isinstance(chain_hex, str) or not isinstance(utxos, dict) or not isinstance(balances, dict):
        return False

    try:
        chain_bytes = bytes.fromhex(chain_hex)
    except ValueError:
        return False

    normalized_utxos: Dict[str, Dict[str, int]] = {}
    for key, entry in utxos.items():
        if not isinstance(entry, dict):
            continue
        address = entry.get("address")
        amount = entry.get("amount_sats")
        txid = entry.get("txid")
        vout = entry.get("vout")
        if not isinstance(address, str) or not isinstance(txid, str):
            continue
        try:
            amount_int = int(amount)
            vout_int = int(vout)
        except (TypeError, ValueError):
            continue
        normalized_utxos[key] = {
            "address": address,
            "amount_sats": amount_int,
            "txid": txid,
            "vout": vout_int,
        }

    normalized_balances: Dict[str, int] = {}
    for key, value in balances.items():
        try:
            normalized_balances[key] = int(value)
        except (TypeError, ValueError):
            continue

    try:
        CHAIN_FILE.write_bytes(chain_bytes)
        UTXO_FILE.write_text(json.dumps(normalized_utxos, separators=(",", ":")))
        BALANCES_FILE.write_text(json.dumps(normalized_balances, separators=(",", ":")))
    except OSError as err:
        print(f"[SYNC] failed to write snapshot: {err}")
        return False

    BLOCKCHAIN.clear()
    _load_blockchain_from_disk()
    UTXO_SET.clear()
    _load_utxos_from_disk()
    BALANCES.clear()
    _load_balances_from_disk()
    _recalculate_balances()
    MEMPOOL.clear()
    print(f"[SYNC] synced chain height {len(BLOCKCHAIN) - 1}")
    return True


def _attempt_sync_from_peers():
    peers = _load_peer_list(DEFAULT_LISTEN_HOST, DEFAULT_P2P_PORT)
    if not peers:
        return
    local_height = len(BLOCKCHAIN) - 1
    default_http_port = int(os.environ.get("SUNNY_HTTP_PORT", "8765"))
    for peer in peers:
        host = peer.get("host")
        if not isinstance(host, str):
            continue
        http_port = peer.get("http_port")
        try:
            http_port = int(http_port)
        except (TypeError, ValueError):
            http_port = default_http_port
        url = f"http://{host}:{http_port}/chain"
        try:
            response = requests.get(url, timeout=5)
        except requests.RequestException:
            continue
        if response.status_code != 200:
            continue
        try:
            payload = response.json()
        except json.JSONDecodeError:
            continue
        remote_height = payload.get("height", -1)
        if not isinstance(remote_height, int):
            continue
        if remote_height <= local_height:
            continue
        if _apply_sync_snapshot(payload):
            break


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


HOST = os.environ.get("SUNNY_HTTP_HOST", "0.0.0.0")
PORT = int(os.environ.get("SUNNY_HTTP_PORT", "8765"))


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
        if parsed.path == "/chain":
            self._handle_chain()
            return
        if parsed.path == "/mempool":
            self._handle_mempool()
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
        if self.path == "/broadcast-tx":
            self._handle_broadcast_tx()
            return
        if self.path == "/broadcast-block":
            self._handle_broadcast_block()
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

    def _handle_chain(self):
        try:
            chain_bytes = CHAIN_FILE.read_bytes()
        except OSError:
            chain_bytes = b""
        data = {
            "height": len(BLOCKCHAIN) - 1,
            "chain_hex": chain_bytes.hex(),
            "utxos": UTXO_SET,
            "balances": BALANCES,
        }
        self._send_json(data)

    def _handle_mempool(self):
        entries = []
        for txid, info in MEMPOOL.items():
            entries.append(
                {
                    "txid": txid,
                    "fee_sats": info.get("fee_sats"),
                    "received_at": info.get("received_at"),
                    "inputs": info.get("inputs", []),
                    "outputs": info.get("outputs", []),
                }
            )
        self._send_json({"mempool": entries})

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

        selected_txs: List[Tx] = []
        spent_in_block = set()
        total_fees = 0
        # select transactions by descending fee
        for txid, info in sorted(
            MEMPOOL.items(), key=lambda item: item[1].get("fee_sats", 0), reverse=True
        ):
            raw_hex = info.get("tx_hex")
            if not raw_hex:
                continue
            try:
                tx = Tx.parse(BytesIO(bytes.fromhex(raw_hex)), testnet=True)
            except Exception:
                continue
            try:
                script_pubkeys = _extract_input_scripts(tx)
            except ValueError:
                continue

            for idx, script in enumerate(script_pubkeys):
                tx.tx_ins[idx].script_pubkey = (  # type: ignore[attr-defined]
                    lambda testnet=True, script=script: script
                )

            temp_spent = []
            conflict = False
            for tx_in in tx.tx_ins:
                key = f"{tx_in.prev_tx.hex()}:{tx_in.prev_index}"
                if key in spent_in_block:
                    conflict = True
                    break
                temp_spent.append(key)
            if conflict:
                continue

            valid = True
            for idx, script in enumerate(script_pubkeys):
                z = tx.sig_hash(idx)
                combined = tx.tx_ins[idx].script_sig + script
                if not combined.evaluate(z):
                    valid = False
                    break
            if not valid:
                continue

            selected_txs.append(tx)
            spent_in_block.update(temp_spent)
            total_fees += info.get("fee_sats") or 0

        block, coinbase_tx = build_candidate_block(
            height,
            prev_block,
            address,
            message=message,
            transactions=selected_txs,
            fees=total_fees,
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

        for tx in selected_txs:
            _apply_confirmed_transaction(tx)
            MEMPOOL.pop(tx.id(), None)

        _persist_utxos()
        _recalculate_balances()
        _persist_balances()

        block_message = {
            "block_hex": mined_block.serialize().hex(),
            "transactions": [tx.serialize().hex() for tx in selected_txs],
            "coinbase_tx": coinbase_tx.serialize().hex(),
            "height": height,
        }
        if P2P_MANAGER is not None:
            P2P_MANAGER.broadcast_block(block_message, origin=NODE_ID)

        result["tx_count"] = len(selected_txs)
        result["fees_sats"] = total_fees
        result["transactions"] = [tx.id() for tx in selected_txs]
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

        if not wif:
            self._send_json({"error": "wif is required to sign transaction"}, status=400)
            return

        try:
            priv, compressed, testnet = _wif_to_private_key(wif)
        except ValueError as exc:
            self._send_json({"error": f"Invalid WIF: {exc}"}, status=400)
            return

        if not testnet:
            self._send_json({"error": "Only testnet WIF keys are supported"}, status=400)
            return

        derived_address = priv.point.address(compressed=compressed, testnet=testnet)
        if derived_address != from_address:
            self._send_json(
                {"error": "WIF does not correspond to from_address"}, status=400
            )
            return

        try:
            from_h160 = decode_base58(from_address)
        except ValueError:
            self._send_json({"error": "Invalid sender address"}, status=400)
            return

        selected_utxos, total_available = _select_utxos(from_address, amount_sats)
        if total_available < amount_sats:
            self._send_json({"error": "Insufficient balance"}, status=400)
            return

        change_sats = total_available - amount_sats
        tx_ins: List[TxIn] = []
        script_pubkeys: List[Script] = []
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
            utxo_address = utxo.get("address")
            if not isinstance(utxo_address, str):
                self._send_json(
                    {"error": f"UTXO {utxo_id} missing address information"},
                    status=500,
                )
                return
            try:
                utxo_h160 = decode_base58(utxo_address)
            except ValueError:
                self._send_json(
                    {"error": f"Stored address for UTXO {utxo_id} is invalid"},
                    status=500,
                )
                return
            script_pubkeys.append(p2pkh_script(utxo_h160))

        tx_outs: List[TxOut] = []
        try:
            to_h160 = decode_base58(to_address)
        except ValueError:
            self._send_json({"error": "Invalid destination address"}, status=400)
            return
        tx_outs.append(TxOut(amount_sats, p2pkh_script(to_h160)))

        if change_sats > 0:
            change_h160 = from_h160
            tx_outs.append(TxOut(change_sats, p2pkh_script(change_h160)))

        tx = Tx(version=1, tx_ins=tx_ins, tx_outs=tx_outs, locktime=0, testnet=True)
        for idx, script in enumerate(script_pubkeys):
            tx.tx_ins[idx].script_pubkey = (  # type: ignore[attr-defined]
                lambda testnet=True, script=script: script
            )

        for idx, script in enumerate(script_pubkeys):
            z = tx.sig_hash(idx)
            der = priv.sign(z).der()
            sig = der + SIGHASH_ALL.to_bytes(1, "big")
            sec = priv.point.sec(compressed=compressed)
            tx.tx_ins[idx].script_sig = Script([sig, sec])
            combined_script = tx.tx_ins[idx].script_sig + script
            if not combined_script.evaluate(z):
                self._send_json(
                    {"error": "Internal signature verification failed"}, status=500
                )
                return

        raw_tx_hex = tx.serialize().hex()
        status, payload, status_code, txid, _ = _accept_transaction(
            raw_tx_hex, origin=NODE_ID
        )
        if status == "error":
            self._send_json(payload, status=status_code)
            return
        if status == "duplicate":
            payload["raw_tx_hex"] = raw_tx_hex
            self._send_json(payload, status=status_code)
            return

        if P2P_MANAGER is not None:
            P2P_MANAGER.broadcast_tx(raw_tx_hex)

        response = {
            "txid": txid,
            "from_address": from_address,
            "to_address": to_address,
            "amount_sats": amount_sats,
            "fee_sats": payload.get("fee_sats", 0),
            "raw_tx_hex": raw_tx_hex,
            "note": "Transaction signed and stored in mempool; broadcasted to peers if configured",
        }
        self._send_json(response, status=201)

    def _handle_broadcast_tx(self):
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

        raw_tx_hex = (payload.get("raw_tx_hex") or payload.get("tx_hex") or "").strip()
        origin_id = payload.get("origin")
        status, result_payload, status_code, txid, stored_hex = _accept_transaction(
            raw_tx_hex, origin=origin_id
        )
        result_payload = result_payload or {}
        if stored_hex is None and raw_tx_hex:
            stored_hex = raw_tx_hex

        if status == "error":
            self._send_json(result_payload, status=status_code)
            return

        if status == "duplicate":
            self._send_json(result_payload, status=status_code)
            return

        broadcast_origin = origin_id or NODE_ID
        if P2P_MANAGER is not None:
            P2P_MANAGER.broadcast_tx(stored_hex, origin=broadcast_origin)

        self._send_json(result_payload, status=status_code)

    def _handle_broadcast_block(self):
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

        block_hex = (payload.get("block_hex") or "").strip()
        if not block_hex:
            self._send_json({"error": "block_hex is required"}, status=400)
            return

        if "coinbase_tx" in payload:
            message = {
                "block_hex": block_hex,
                "coinbase_tx": payload.get("coinbase_tx"),
                "transactions": payload.get("transactions") or [],
                "height": payload.get("height"),
            }
            previous_height = len(BLOCKCHAIN)
            _handle_incoming_block_from_peer(message, origin=payload.get("origin"))
            if len(BLOCKCHAIN) > previous_height:
                self._send_json(
                    {
                        "status": "accepted",
                        "height": len(BLOCKCHAIN) - 1,
                        "hash": BLOCKCHAIN[-1].hash().hex(),
                    },
                    status=202,
                )
            else:
                self._send_json({"status": "ignored"}, status=200)
            return

        try:
            block_bytes = bytes.fromhex(block_hex)
        except ValueError:
            self._send_json({"error": "block_hex must be valid hex"}, status=400)
            return

        if len(block_bytes) != 80:
            self._send_json({"error": "Only 80-byte block headers supported"}, status=400)
            return

        block = Block.parse(BytesIO(block_bytes))
        if not block.check_pow():
            self._send_json({"error": "Invalid proof-of-work"}, status=400)
            return

        prev_hash = block.prev_block.hex()
        expected_prev = (
            BLOCKCHAIN[-1].hash().hex() if BLOCKCHAIN else "00" * 32
        )
        if prev_hash != expected_prev:
            self._send_json(
                {
                    "error": "Block does not extend current chain",
                    "expected_prev": expected_prev,
                    "provided_prev": prev_hash,
                },
                status=409,
            )
            return

        BLOCKCHAIN.append(block)
        try:
            with open("genesis_block.bin", "ab") as f:
                f.write(block.serialize())
        except OSError as err:
            self._send_json({"error": f"Failed to persist block: {err}"}, status=500)
            return

        self._send_json(
            {"status": "accepted", "height": len(BLOCKCHAIN) - 1, "hash": block.hash().hex()},
            status=202,
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
    try:
        _attempt_sync_from_peers()
    except Exception as exc:  # noqa: BLE001
        print(f"[SYNC] initial sync failed: {exc}")
    try:
        listen_host = os.environ.get("SUNNY_P2P_HOST", DEFAULT_LISTEN_HOST)
        listen_port = int(os.environ.get("SUNNY_P2P_PORT", str(DEFAULT_P2P_PORT)))
        P2P_MANAGER = PeerManager(
            NODE_ID,
            listen_host=listen_host,
            listen_port=listen_port,
            on_tx=_handle_incoming_tx_from_peer,
            on_block=_handle_incoming_block_from_peer,
        )
        P2P_MANAGER.start()
        print(f"[P2P] node_id={NODE_ID} listening on {listen_host}:{listen_port}")
    except Exception as exc:  # noqa: BLE001
        print(f"Warning: unable to start P2P server: {exc}")
        P2P_MANAGER = None

    try:
        HTTPServer((HOST, PORT), AddressHandler).serve_forever()
    finally:
        if P2P_MANAGER is not None:
            P2P_MANAGER.stop()
