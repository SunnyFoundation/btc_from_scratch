import json
import os
import socket
import threading
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional, Tuple

DEFAULT_P2P_PORT = int(os.environ.get("SUNNY_P2P_PORT", "18765"))
DEFAULT_LISTEN_HOST = os.environ.get("SUNNY_P2P_HOST", "0.0.0.0")
PEERS_FILE = Path("peers.json")


def _load_peer_list(self_host: str, self_port: int) -> List[Dict[str, int]]:
    if not PEERS_FILE.exists():
        return []
    try:
        payload = json.loads(PEERS_FILE.read_text())
    except (OSError, json.JSONDecodeError):
        return []
    peers: List[Dict[str, int]] = []
    if isinstance(payload, list):
        for entry in payload:
            if not isinstance(entry, dict):
                continue
            host = entry.get("host")
            port = entry.get("port", DEFAULT_P2P_PORT)
            if not isinstance(host, str):
                continue
            if not isinstance(port, int):
                continue
            if host == self_host and port == self_port:
                continue
            peers.append({"host": host, "port": port})
    return peers


def _encode_message(message: Dict) -> bytes:
    return json.dumps(message, separators=(",", ":")).encode("utf-8") + b"\n"


class PeerManager:
    def __init__(
        self,
        node_id: str,
        *,
        listen_host: str = DEFAULT_LISTEN_HOST,
        listen_port: int = DEFAULT_P2P_PORT,
        peers: Optional[Iterable[Dict[str, int]]] = None,
        on_tx: Optional[Callable[[str, Optional[str]], None]] = None,
    ) -> None:
        self.node_id = node_id
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.on_tx = on_tx
        self._server_socket: Optional[socket.socket] = None
        self._server_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.peers: List[Dict[str, int]] = list(peers) if peers is not None else []
        if not self.peers:
            self.peers = _load_peer_list(self.listen_host, self.listen_port)

    def start(self) -> None:
        if self._server_thread and self._server_thread.is_alive():
            return
        self._stop_event.clear()
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self.listen_host, self.listen_port))
        self._server_socket.listen()
        self._server_thread = threading.Thread(
            target=self._server_loop, name="p2p-listener", daemon=True
        )
        self._server_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

    def broadcast_tx(self, raw_tx_hex: str, origin: Optional[str] = None) -> None:
        if not raw_tx_hex:
            return
        origin_id = origin or self.node_id
        message = _encode_message({"type": "tx", "tx_hex": raw_tx_hex, "origin": origin_id})
        for peer in self.peers:
            host = peer.get("host")
            port = peer.get("port")
            if host is None or port is None:
                continue
            if host in ("127.0.0.1", "localhost", self.listen_host) and port == self.listen_port:
                continue
            try:
                with socket.create_connection((host, port), timeout=3) as sock:
                    sock.sendall(message)
            except OSError:
                continue

    def _server_loop(self) -> None:
        assert self._server_socket is not None
        while not self._stop_event.is_set():
            try:
                self._server_socket.settimeout(1.0)
                conn, _ = self._server_socket.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(
                target=self._handle_connection,
                args=(conn,),
                name="p2p-peer",
                daemon=True,
            ).start()

    def _handle_connection(self, conn: socket.socket) -> None:
        with conn:
            conn.settimeout(5.0)
            buffer = b""
            while not self._stop_event.is_set():
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buffer += chunk
                while b"\n" in buffer:
                    line, buffer = buffer.split(b"\n", 1)
                    self._handle_line(line)

    def _handle_line(self, line: bytes) -> None:
        line = line.strip()
        if not line:
            return
        try:
            message = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return
        if not isinstance(message, dict):
            return
        msg_type = message.get("type")
        if msg_type != "tx":
            return
        raw_tx_hex = message.get("tx_hex")
        if not isinstance(raw_tx_hex, str):
            return
        origin = message.get("origin")
        if isinstance(origin, str) and origin == self.node_id:
            return
        if self.on_tx:
            try:
                self.on_tx(raw_tx_hex, origin if isinstance(origin, str) else None)
            except Exception:
                pass
