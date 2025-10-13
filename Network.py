from Block import Block
from io import BytesIO
from random import randint
import socket
import time
from helper import (
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    decode_base58,
    hash160,
    encode_varint,
)

NETWORK_MAGIC = b"\xf9\xbe\xb4\xd9"
TESTNET_NETWORK_MAGIC = b"\x0b\x11\x09\x07"

GENESIS_BLOCK = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
)
TESTNET_GENESIS_BLOCK = bytes.fromhex(
    "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4adae5494dffff001d1aa4ae18"
)
LOWEST_BITS = bytes.fromhex("ffff001d")


class NetworkEnvelope:
    def __init__(self, command, payload, testnet=False):
        self.command = command
        self.payload = payload
        if testnet:
            self.magic = TESTNET_NETWORK_MAGIC
        else:
            self.magic = NETWORK_MAGIC

    def __repr__(self):
        return "{} : {}".format(
            self.command.decode("ascii"),
            self.payload.hex(),
        )

    @classmethod
    def parse(cls, s, testnet=False):
        magic = s.read(4)
        if magic == b"":
            raise IOError("Connection reset!")
        if testnet:
            expected_magic = TESTNET_NETWORK_MAGIC
        else:
            expected_magic = NETWORK_MAGIC
        if magic != expected_magic:
            raise SyntaxError(
                "magic is not right {} vs {}".format(magic.hex(), expected_magic.hex())
            )
        command = s.read(12)
        command = command.strip(b"\x00")
        payload_length = little_endian_to_int(s.read(4))
        checksum = s.read(4)
        payload = s.read(payload_length)
        calculated_checksum = hash256(payload)[:4]
        if calculated_checksum != checksum:
            raise IOError("checksum does not match")
        return cls(command, payload, testnet=testnet)

    def serialize(self):
        result = self.magic
        result += self.command + b"\x00" * (12 - len(self.command))
        result += int_to_little_endian(len(self.payload), 4)
        result += hash256(self.payload)[:4]
        result += self.payload
        return result


class VersionMessage:
    command = b"version"

    def __init__(
        self,
        version=70015,
        services=0,
        timestamp=None,
        receiver_services=0,
        receiver_ip=b"\x00\x00\x00\x00",
        receiver_port=8333,
        sender_services=0,
        sender_ip=b"\x00\x00\x00\x00",
        sender_port=8333,
        nonce=None,
        user_agent=b"/programmingbitcoin:0.1/",
        latest_block=0,
        relay=False,
    ):
        self.version = version
        self.services = services
        if timestamp is None:
            self.timestamp = int(time.time())
        else:
            self.timestamp = timestamp
        self.receiver_services = receiver_services
        self.receiver_ip = receiver_ip
        self.receiver_port = receiver_port
        self.sender_services = sender_services
        self.sender_ip = sender_ip
        self.sender_port = sender_port
        if nonce is None:
            self.nonce = int_to_little_endian(randint(0, 2**64), 8)
        else:
            self.nonce = nonce
        self.user_agent = user_agent
        self.latest_block = latest_block
        self.relay = relay

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += int_to_little_endian(self.services, 8)
        result += int_to_little_endian(self.timestamp, 8)
        result += int_to_little_endian(self.receiver_services, 8)
        result += b"\x00" * 10 + b"\xff\xff" + self.receiver_ip
        result += self.receiver_port.to_bytes(2, "big")
        result += int_to_little_endian(self.sender_services, 8)
        result += b"\x00" * 10 + b"\xff\xff" + self.sender_ip
        result += self.sender_port.to_bytes(2, "big")
        result += self.nonce
        result += encode_varint(len(self.user_agent))
        result += self.user_agent
        result += int_to_little_endian(self.latest_block, 4)
        if self.relay:
            result += b"\x01"
        else:
            result += b"\x00"
        return result


class VerAckMessage:
    command = b"verack"

    def __init__(self):
        pass

    @classmethod
    def parse(cls, s):
        return cls()

    def serialize(self):
        return b""


class PingMessage:
    command = b"ping"

    def __init__(self, nonce):
        self.nonce = nonce

    @classmethod
    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class PongMessage:
    command = b"pong"

    def __init__(self, nonce):
        self.nonce = nonce

    def parse(cls, s):
        nonce = s.read(8)
        return cls(nonce)

    def serialize(self):
        return self.nonce


class SimpleNode:

    def __init__(self, host, port=None, testnet=False, logging=False):
        if port is None:
            if testnet:
                port = 18333
            else:
                port = 8333
        self.testnet = testnet
        self.logging = logging
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((host, port))
        self.stream = self.socket.makefile("rb", None)

    # end::source4[]

    def handshake(self):
        version = VersionMessage()
        self.send(version)
        self.wait_for(VerAckMessage)

    def send(self, message):  # <1>
        """Send a message to the connected node"""
        envelope = NetworkEnvelope(
            message.command, message.serialize(), testnet=self.testnet
        )
        if self.logging:
            print("sending: {}".format(envelope))
        self.socket.sendall(envelope.serialize())

    def read(self):  # <2>
        """Read a message from the socket"""
        envelope = NetworkEnvelope.parse(self.stream, testnet=self.testnet)
        if self.logging:
            print("receiving: {}".format(envelope))
        return envelope

    def wait_for(self, *message_classes):  # <3>
        """Wait for one of the messages in the list"""
        command = None
        command_to_class = {m.command: m for m in message_classes}
        while command not in command_to_class.keys():
            envelope = self.read()
            command = envelope.command
            if command == VersionMessage.command:
                self.send(VerAckMessage())
            elif command == PingMessage.command:
                self.send(PongMessage(envelope.payload))
        return command_to_class[command].parse(BytesIO(envelope.payload))


class GetHeadersMessage:
    command = b"getheaders"

    def __init__(self, version=70015, num_hashes=1, start_block=None, end_block=None):
        self.version = version
        self.num_hashes = num_hashes  # <1>
        if start_block is None:  # <2>
            raise RuntimeError("a start block is required")
        self.start_block = start_block
        if end_block is None:
            self.end_block = b"\x00" * 32  # <3>
        else:
            self.end_block = end_block

    # end::source5[]

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(self.num_hashes)
        result += self.start_block[::-1]
        result += self.end_block[::-1]
        return result


class HeadersMessage:
    command = b"headers"

    def __init__(self, blocks):
        self.blocks = blocks

    @classmethod
    def parse(cls, stream):
        num_headers = read_varint(stream)
        blocks = []
        for _ in range(num_headers):
            blocks.append(Block.parse(stream))  # <1>
            num_txs = read_varint(stream)  # <2>
            if num_txs != 0:  # <3>
                raise RuntimeError("number of txs not 0")
        return cls(blocks)


# ===========================================================
# 🧩 (1) verack 메시지 테스트 — 기본 네트워크 패킷 파싱 실습
# ===========================================================
# verack 메시지는 payload가 없는 아주 간단한 메시지입니다.
# 네트워크에서 받은 raw hex 데이터를 NetworkEnvelope으로 파싱해봅니다.
# ===========================================================
# message_hex = "f9beb4d976657261636b000000000000000000005df6e0e2"
# stream = BytesIO(bytes.fromhex(message_hex))
# envelope = NetworkEnvelope.parse(stream)
# print(envelope.command)  # b'verack'
# print(envelope.payload)  # b''


# ===========================================================
# 🧩 (2) version 메시지 파싱 테스트 — 네트워크 초기 핸드셰이크 메시지
# ===========================================================
# version 메시지는 노드 간 연결 시 “나는 이런 버전이야” 하고 교환하는 메시지입니다.
# payload에 노드 정보(IP, 포트, timestamp, user_agent 등)가 포함됩니다.
# ===========================================================
# msg = bytes.fromhex(
#     "f9beb4d976657273696f6e0000000000650000005f1a69d2721101000100000000000000bc8f5e5400000000010000000000000000000000000000000000ffffc61b6409208d010000000000000000000000000000000000ffffcb0071c0208d128035cbc97953f80f2f5361746f7368693a302e392e332fcf05050001"
# )
# stream = BytesIO(msg)
# envelope = NetworkEnvelope.parse(stream)
# print(envelope.command)  # b'version'
# print(envelope.payload)  # 실제 payload 바이트 출력


# ===========================================================
# 🧩 (3) version 메시지 직접 생성 테스트 — 내가 version 만들기
# ===========================================================
# VersionMessage 객체를 serialize() 해서 실제 전송 가능한 형태로 만들어봅니다.
# ===========================================================
# msg = VersionMessage()
# serialized = msg.serialize()
# print(serialized.hex())  # 직렬화된 버전 메시지 출력


# ===========================================================
# 🧩 (4) 테스트넷 노드와 실제 핸드셰이크 수행
# ===========================================================
# testnet.programmingbitcoin.com 노드에 연결하여
# version ↔ verack 교환을 실제로 수행합니다.
# ===========================================================
# node = SimpleNode("testnet.programmingbitcoin.com", testnet=True, logging=True)
# node.handshake()


# ===========================================================
# 🧩 (5) getheaders 요청 보내기 — 헤더 요청 메시지 실험
# ===========================================================
# start_block 이후의 블록 헤더들을 요청하는 메시지입니다.
# 블록체인 헤더 동기화의 기본 단위입니다.
# ===========================================================
# start_block = bytes.fromhex(
#     "0000000000000000000b4d0b31f5c15ed7aafb5b813cf5e478c7c5a30e2b2ff9"
# )
# msg = GetHeadersMessage(start_block=start_block)
# envelope = NetworkEnvelope(msg.command, msg.serialize(), testnet=True)
# node.send(msg)


# ===========================================================
# 🧩 (6) 헤더 동기화 루프 — 블록체인 난이도 조정 실험
# ===========================================================
# 1️⃣ 테스트넷 제네시스 블록에서 시작
# 2️⃣ getheaders → headers 메시지 반복으로 블록 헤더 받기
# 3️⃣ 각 블록의 PoW, prev_block 연결성 검증
# 4️⃣ 2016블록마다 난이도 재계산 (calculate_new_bits)
# ===========================================================
# previous = Block.parse(BytesIO(TESTNET_GENESIS_BLOCK))
# first_epoch_timestamp = previous.timestamp
# expected_bits = LOWEST_BITS
# count = 1
# node = SimpleNode("testnet.programmingbitcoin.com", testnet=True)
# node.handshake()
# for _ in range(19):
#     getheaders = GetHeadersMessage(start_block=previous.hash())
#     node.send(getheaders)
#     headers = node.wait_for(HeadersMessage)
#     for header in headers.blocks:
#         if not header.check_pow():
#             raise RuntimeError(f"bad PoW at block {count}")
#         if header.prev_block != previous.hash():
#             raise RuntimeError(f"discontinuous block at {count}")
#         if count % 2016 == 0:
#             time_diff = previous.timestamp - first_epoch_timestamp
#             expected_bits = Block.calculate_new_bits(previous.bits, time_diff)
#             print(f"[difficulty adjusted] new bits = {expected_bits.hex()}")
#             first_epoch_timestamp = header.timestamp
#         # ✅ 테스트넷에서는 bits 불일치 무시
#         if not node.testnet and header.bits != expected_bits:
#             raise RuntimeError(f"bad bits at block {count}")
#         previous = header
#         count += 1


# ===========================================================
# 🧩 (7) 출력 결과 — 난이도 조정 로그
# ===========================================================
# 실제 테스트넷 블록 데이터를 통해 매 2016블록마다
# 새로운 난이도(bits) 값이 계산되어 출력됩니다.
# 테스트넷은 메인넷보다 자주 난이도를 리셋하기 때문에
# 값이 들쭉날쭉하게 보이는 것이 정상입니다.
# ===========================================================
# [difficulty adjusted] new bits = fcff031d
# [difficulty adjusted] new bits = c0ff3f1c
# [difficulty adjusted] new bits = f0ff0f1c
# [difficulty adjusted] new bits = c0ff3f1c
# [difficulty adjusted] new bits = ffff001d
# [difficulty adjusted] new bits = c0ff3f1c
# [difficulty adjusted] new bits = f0ff0f1c
# [difficulty adjusted] new bits = ae0d171c
# [difficulty adjusted] new bits = b508481c
