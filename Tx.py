from io import BytesIO
from Script import Script
from Script import p2pkh_script
import json
import requests
from Ecc import PrivateKey


from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    decode_base58,
    hash160,
    SIGHASH_ALL,
)


class TxFetcher:
    cache = {}

    @classmethod
    def get_url(cls, testnet=False):
        if testnet:
            return "https://blockstream.info/testnet/api/"
        else:
            return "https://blockstream.info/api/"

    @classmethod
    def fetch(cls, tx_id, testnet=False, fresh=False):
        if fresh or (tx_id not in cls.cache):
            url = "{}/tx/{}/hex".format(cls.get_url(testnet), tx_id)
            response = requests.get(url)
            try:
                raw = bytes.fromhex(response.text.strip())
            except ValueError:
                raise ValueError("unexpected response: {}".format(response.text))
            if raw[4] == 0:
                raw = raw[:4] + raw[6:]
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
                tx.locktime = little_endian_to_int(raw[-4:])
            else:
                tx = Tx.parse(BytesIO(raw), testnet=testnet)
            if tx.id() != tx_id:  # <1>
                raise ValueError("not the same id: {} vs {}".format(tx.id(), tx_id))
            cls.cache[tx_id] = tx
        cls.cache[tx_id].testnet = testnet
        return cls.cache[tx_id]


class Tx:

    def __init__(self, version, tx_ins, tx_outs, locktime, testnet=False):
        self.version = version
        self.tx_ins = tx_ins  # <1>
        self.tx_outs = tx_outs
        self.locktime = locktime
        self.testnet = testnet  # <2>

    def __repr__(self):
        tx_ins = ""
        for tx_in in self.tx_ins:
            tx_ins += tx_in.__repr__() + "\n"
        tx_outs = ""
        for tx_out in self.tx_outs:
            tx_outs += tx_out.__repr__() + "\n"
        return "tx: {}\nversion: {}\ntx_ins:\n{}tx_outs:\n{}locktime: {}".format(
            self.id(),
            self.version,
            tx_ins,
            tx_outs,
            self.locktime,
        )

    def is_coinbase(self):
        if len(self.tx_ins) != 1:
            return False
        first_input = self.tx_ins[0]
        if first_input.prev_tx != b"\x00" * 32:
            return False
        if first_input.prev_index != 0xFFFFFFFF:
            return False
        return True

    def coinbase_height(self):
        if not self.is_coinbase():
            return None
        element = self.tx_ins[0].script_sig.cmds[0]
        return little_endian_to_int(element)

    def id(self):  # <3>
        # Good for human
        return self.hash().hex()

    def hash(self):  # <4>
        # Good for computer
        return hash256(self.serialize())[::-1]

    @classmethod
    def parse(cls, s, testnet=False):
        version = little_endian_to_int(s.read(4))
        num_inputs = read_varint(s)
        inputs = []
        for _ in range(num_inputs):
            inputs.append(TxIn.parse(s))

        num_outputs = read_varint(s)
        outputs = []
        for _ in range(num_outputs):
            outputs.append(TxOut.parse(s))
        locktime = little_endian_to_int(s.read(4))
        return cls(version, inputs, outputs, locktime, testnet=testnet)

    def serialize(self):
        result = int_to_little_endian(self.version, 4)
        result += encode_varint(len(self.tx_ins))
        for tx_in in self.tx_ins:
            result += tx_in.serialize()
        result += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            result += tx_out.serialize()
        result += int_to_little_endian(self.locktime, 4)
        return result

    def fee(self, testnet=False):
        input_sum, output_sum = 0, 0
        for tx_in in self.tx_ins:
            input_sum += tx_in.value(testnet=testnet)
        for tx_out in self.tx_outs:
            output_sum += tx_out.amount
        return input_sum - output_sum

    # 내가 쓰고싶은 input에다가 잠금스크립트를 삽입함
    def sig_hash(self, input_index):
        s = int_to_little_endian(self.version, 4)
        s += encode_varint(len(self.tx_ins))
        for i, tx_in in enumerate(self.tx_ins):
            if i == input_index:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    script_sig=tx_in.script_pubkey(self.testnet),
                    sequence=tx_in.sequence,
                ).serialize()
            else:
                s += TxIn(
                    prev_tx=tx_in.prev_tx,
                    prev_index=tx_in.prev_index,
                    sequence=tx_in.sequence,
                ).serialize()
        s += encode_varint(len(self.tx_outs))
        for tx_out in self.tx_outs:
            s += tx_out.serialize()
        s += int_to_little_endian(self.locktime, 4)
        s += int_to_little_endian(SIGHASH_ALL, 4)
        h256 = hash256(s)
        return int.from_bytes(h256, "big")

    def verify(self):
        """Verify this transaction"""
        if self.fee() < 0:  # <1>
            return False
        for i in range(len(self.tx_ins)):
            if not self.verify_input(i):  # <2>
                return False
        return True

    def verify_input(self, input_index):
        tx_in = self.tx_ins[input_index]
        script_pubkey = tx_in.script_pubkey(testnet=True)
        z = self.sig_hash(input_index)
        combined = tx_in.script_sig + script_pubkey
        return combined.evaluate(z)

    def sign_input(self, input_index, private_key):
        z = self.sig_hash(input_index)

        der = private_key.sign(z).der()
        sig = der + SIGHASH_ALL.to_bytes(1, "big")
        sec = private_key.point.sec()
        self.tx_ins[input_index].script_sig = Script([sig, sec])
        return self.verify_input(input_index)


class TxIn:
    def __init__(self, prev_tx, prev_index, script_sig=None, sequence=0xFFFFFFFF):
        self.prev_tx = prev_tx
        self.prev_index = prev_index
        if script_sig is None:  # <1>
            self.script_sig = Script()
        else:
            self.script_sig = script_sig
        self.sequence = sequence

    def __repr__(self):
        return "{}:{}".format(
            self.prev_tx.hex(),
            self.prev_index,
        )

    @classmethod
    def parse(cls, s):
        prev_tx = s.read(32)[::-1]
        prev_index = little_endian_to_int(s.read(4))
        script_sig = Script.parse(s)
        sequence = little_endian_to_int(s.read(4))
        return cls(prev_tx, prev_index, script_sig, sequence)

    def serialize(self):
        result = self.prev_tx[::-1]
        result += int_to_little_endian(self.prev_index, 4)
        result += self.script_sig.serialize()
        result += int_to_little_endian(self.sequence, 4)
        return result

    def fetch_tx(self, testnet=True):
        return TxFetcher.fetch(self.prev_tx.hex(), testnet=testnet)

    def value(self, testnet=True):
        """Get the output value by looking up the tx hash.
        Returns the amount in satoshi.
        """
        tx = self.fetch_tx(testnet=testnet)
        return tx.tx_outs[self.prev_index].amount

    def script_pubkey(self, testnet=True):
        """Get the ScriptPubKey by looking up the tx hash.
        Returns a Script object.
        """
        tx = self.fetch_tx(testnet=True)
        return tx.tx_outs[self.prev_index].script_pubkey


class TxOut:

    def __init__(self, amount, script_pubkey):
        self.amount = amount
        self.script_pubkey = script_pubkey

    def __repr__(self):
        return "{}:{}".format(self.amount, self.script_pubkey)

    @classmethod
    def parse(cls, s):
        amount = little_endian_to_int(s.read(8))
        script_pubkey = Script.parse(s)
        return cls(amount, script_pubkey)

    def serialize(self):  # <1>
        """Returns the byte serialization of the transaction output"""
        result = int_to_little_endian(self.amount, 8)
        result += self.script_pubkey.serialize()
        return result


def encode_coinbase_height(height):
    """Encode block height using the minimal little-endian format (BIP34)."""
    if height < 0:
        raise ValueError("height must be non-negative")
    if height == 0:
        return b"\x00"
    encoded = bytearray()
    while height:
        encoded.append(height & 0xFF)
        height >>= 8
    if encoded[-1] & 0x80:
        encoded.append(0x00)
    return bytes(encoded)


def create_coinbase_tx(block_height, address, subsidy_sats, message=b"", testnet=True):
    """Build a coinbase transaction paying the subsidy to the given address."""
    if isinstance(message, str):
        message = message.encode("utf-8")
    height_field = encode_coinbase_height(block_height)
    script_cmds = [height_field]
    if message:
        script_cmds.append(message)
    coinbase_input = TxIn(
        prev_tx=b"\x00" * 32,
        prev_index=0xFFFFFFFF,
        script_sig=Script(script_cmds),
        sequence=0xFFFFFFFF,
    )
    h160 = decode_base58(address)
    reward_output = TxOut(subsidy_sats, p2pkh_script(h160))
    return Tx(1, [coinbase_input], [reward_output], 0, testnet=testnet)


# Tx Fetcher

# txid = "e8336763b819f81ddd6e6849f01f17fec034f4220835fe3892802b105e2543a6"

# # 트랜잭션 가져오기
# tx = TxFetcher.fetch(txid, testnet=True)
# print(tx)
# # 첫 번째 입력 선택
# first_input = tx.tx_ins[0]

# # print("=== TxIn 정보 ===")
# print("이 TxIn이 참조하는 이전 트랜잭션 ID:", first_input.prev_tx.hex())
# print("이전 트랜잭션에서 참조한 Output 번호:", first_input.prev_index)

# # (1) fetch_tx 사용 → 이전 트랜잭션 전체 가져오기
# prev_tx = first_input.fetch_tx(testnet=True)
# # print("\n=== fetch_tx 결과 (이전 트랜잭션) ===")
# print(prev_tx)

# # (2) value 사용 → 참조한 Output의 금액 확인
# amount_satoshi = first_input.value(testnet=True)
# # print("\n=== value 결과 ===")
# print("이 TxIn이 참조하는 Output 금액:", amount_satoshi, "satoshi")
# # print("BTC 단위로 환산:", amount_satoshi / 100_000_000, "BTC")

# # (3) script_pubkey 사용 → 참조한 Output의 Script 확인
# script_pubkey = first_input.script_pubkey(testnet=True)
# print("\n=== script_pubkey 결과 ===")
# print(script_pubkey)


# fee_satoshi = tx.fee(testnet=True)

# print("=== Fee 계산 결과 ===")
# print("수수료 (satoshi):", fee_satoshi)


# prev_tx = bytes.fromhex(
#     "e8336763b819f81ddd6e6849f01f17fec034f4220835fe3892802b105e2543a6"
# )
# prev_index = 1
# tx_in = TxIn(prev_tx, prev_index)
# tx_outs = []
# change_amount = int(0.33 * 100000000)  # <1>
# change_h160 = decode_base58("moMgoV8ouE3i6cQ96PNRcQ63jPonhztGME")
# change_script = p2pkh_script(change_h160)
# change_output = TxOut(amount=change_amount, script_pubkey=change_script)
# target_amount = int(0.1 * 100000000)  # <1>
# target_h160 = decode_base58("mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf")
# target_script = p2pkh_script(target_h160)
# target_output = TxOut(amount=target_amount, script_pubkey=target_script)
# tx_obj = Tx(1, [tx_in], [change_output, target_output], 0, True)  # <2>


# print(tx_obj.serialize().hex())


# prev_tx = bytes.fromhex(
#     "e8336763b819f81ddd6e6849f01f17fec034f4220835fe3892802b105e2543a6"
# )
# prev_index = 0
# target_address = "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
# target_amount = 0.0005
# change_address = "moMgoV8ouE3i6cQ96PNRcQ63jPonhztGME"
# change_amount = 0.0006
# secret = 205654419802215262823383638835045262042916840092792866665560957952008811891
# priv = PrivateKey(secret=secret)
# tx_ins = []
# tx_ins.append(TxIn(prev_tx, prev_index))
# tx_outs = []
# h160 = decode_base58(target_address)
# script_pubkey = p2pkh_script(h160)
# target_satoshis = int(target_amount * 100000000)
# tx_outs.append(TxOut(target_satoshis, script_pubkey))
# h160 = decode_base58(change_address)
# script_pubkey = p2pkh_script(h160)
# change_satoshis = int(change_amount * 100000000)
# tx_outs.append(TxOut(change_satoshis, script_pubkey))
# tx_obj = Tx(1, tx_ins, tx_outs, 0, testnet=True)
# print(tx_obj)
# print(tx_obj.sign_input(0, priv))
# print(tx_obj.serialize().hex())

# 0100000001a643255e102b809238fe350822f434c0fe171ff049686edd1df819b8636733e8000000006b483045022100b251e5d80ae45f13338b4556f3a84618fdeda807a9bdb805ddfb255be18ed5c402201109efad4020cde0790ba5f1fe5b1bb1a0c06da128ae793e222cde9cf6b9f549012103bd39242c1a11b75811ddc46d75a6a03932d6c926db4d12bcd79ce3141f7eb91affffffff0250c30000000000001976a914507b27411ccf7f16f10297de6cef3f291623eddf88ac5fea0000000000001976a91456005480375868d337081b9c08525d78d507ba5988ac00000000
