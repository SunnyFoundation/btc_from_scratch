import time
from io import BytesIO

from Tx import create_coinbase_tx

from helper import (
    decode_base58,
    encode_varint,
    hash160,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    merkle_root,
    bits_to_target,
    read_varint,
    target_to_bits,
    TWO_WEEKS,
)


class Block:
    def __init__(
        self,
        version,
        prev_block,
        merkle_root_bytes,
        timestamp,
        bits,
        nonce,
        tx_hashes=None,
    ):
        self.version = version
        self.prev_block = prev_block
        self.merkle_root_bytes = merkle_root_bytes
        self.timestamp = timestamp
        self.bits = bits
        self.nonce = nonce
        self.tx_hashes = tx_hashes

    @classmethod
    def parse(cls, s):
        version = little_endian_to_int(s.read(4))
        prev_block = s.read(32)[::-1]  # network에서 읽을 때 big→little 변환
        merkle_root = s.read(32)[::-1]
        timestamp = little_endian_to_int(s.read(4))
        bits = s.read(4)
        nonce = s.read(4)
        return cls(version, prev_block, merkle_root, timestamp, bits, nonce)

    def serialize(self):
        version_bytes = int_to_little_endian(self.version, 4)
        prev_block_bytes = self.prev_block[::-1]  # little→big 복원
        merkle_root_bytes = self.merkle_root_bytes[::-1]
        timestamp_bytes = int_to_little_endian(self.timestamp, 4)
        bits_bytes = self.bits
        nonce_bytes = self.nonce
        return (
            version_bytes
            + prev_block_bytes
            + merkle_root_bytes
            + timestamp_bytes
            + bits_bytes
            + nonce_bytes
        )

    def hash(self):
        s = self.serialize()
        sha = hash256(s)
        return sha[::-1]

    def bip9(self):
        return self.version >> 29 == 0b001

    def bip91(self):
        return self.version >> 4 & 1 == 1

    def bip141(self):
        return self.version >> 1 & 1 == 1

    def target(self):
        """Returns the proof-of-work target based on the bits"""
        return bits_to_target(self.bits)

    def difficulty(self):
        lowest = 0xFFFF * 256 ** (0x1D - 3)
        return lowest / self.target()

    def check_pow(self):
        proof = self.hash()
        target_value = self.target().to_bytes(32, "big")
        return proof < target_value

    @staticmethod
    def calculate_new_bits(previous_bits, time_differential):
        if (
            time_differential > TWO_WEEKS * 4
        ):  # 시간차이가 8주보다 크다면 그냥 8주로 박음
            time_differential = TWO_WEEKS * 4
        if (
            time_differential < TWO_WEEKS // 4
        ):  # 시간차이가 3.5일보다 작으면 그냥 그냥 3.5일로 박음
            time_differential = TWO_WEEKS // 4
        new_target = bits_to_target(previous_bits) * time_differential // TWO_WEEKS
        return target_to_bits(new_target)

    def mine(self, start_nonce=0, max_nonce=0xFFFFFFFF):
        """
        채굴 시도 함수.
        nonce를 0부터 하나씩 증가시키며 check_pow()가 True가 될 때까지 반복.
        """
        target = self.target()
        print(f"Mining... target = {hex(target)}")

        start_time = time.time()
        for nonce in range(start_nonce, max_nonce):
            self.nonce = int_to_little_endian(nonce, 4)
            hash_value = hash256(self.serialize())
            # 비교 시 little-endian → big-endian으로 뒤집기
            if hash_value[::-1] < target.to_bytes(32, "big"):
                elapsed = time.time() - start_time
                print(f"✅ Found! Nonce = {nonce}, Hash = {hash_value[::-1].hex()}")
                print(f"Elapsed: {elapsed:.2f} sec")
                return nonce
            if nonce % 1000000 == 0:
                print(f"Checked nonce {nonce}... still mining")

        print("❌ No valid nonce found in range.")
        return None

    def validate_merkle_root(self):
        hashes = [h[::-1] for h in self.tx_hashes]
        root = merkle_root(hashes)
        return root[::-1] == self.merkle_root_bytes


DEFAULT_BITS = b"\xff\xff\x07\x1e"
DEFAULT_SUBSIDY = 6_2500_0000  # 6.25 BTC expressed in satoshis


def build_candidate_block(
    height,
    prev_block,
    address,
    *,
    subsidy=DEFAULT_SUBSIDY,
    bits=DEFAULT_BITS,
    message="",
    timestamp=None,
    transactions=None,
    fees=0,
):
    """
    Construct a block header ready for mining.
    Returns the block instance and the coinbase transaction.
    """
    if timestamp is None:
        timestamp = int(time.time())

    reward = subsidy + (fees or 0)
    coinbase_tx = create_coinbase_tx(height, address, reward, message=message)

    txs = [coinbase_tx] + (transactions or [])

    tx_hashes_be = [bytes.fromhex(tx.id()) for tx in txs]
    merkle_root_be = merkle_root(tx_hashes_be)
    tx_hashes_le = [h[::-1] for h in tx_hashes_be]

    block = Block(
        version=1,
        prev_block=prev_block,
        merkle_root_bytes=merkle_root_be[::-1],
        timestamp=timestamp,
        bits=bits,
        nonce=b"\x00\x00\x00\x00",
        tx_hashes=tx_hashes_le,
    )
    return block, coinbase_tx


def mine_block(block, start_nonce=0, max_nonce=0xFFFFFFFF):
    """
    Wrapper around Block.mine that returns the mined block on success.
    """
    nonce = block.mine(start_nonce=start_nonce, max_nonce=max_nonce)
    if nonce is None:
        return None
    return block


if __name__ == "__main__":
    # Demonstration: mine and persist a genesis block locally.
    height = 0
    address = "mnrVtF8DWjMu839VW3rBfgYaAfKk8983Xf"
    block0, _ = build_candidate_block(
        height,
        prev_block=b"\x00" * 32,
        address=address,
        message="sunny genesis block",
    )
    mined_block = mine_block(block0)
    is_valid = mined_block.check_pow() if mined_block else False
    print("Valid:", is_valid)

    if is_valid:
        print("✅ Genesis block mined successfully!")
        with open("genesis_block.bin", "wb") as f:
            f.write(mined_block.serialize())
        print("✅ Saved as genesis_block.bin")
    else:
        print("❌ Invalid block, not saved.")

    if mined_block:
        print("✅ Genesis block mined:", mined_block.hash().hex())
