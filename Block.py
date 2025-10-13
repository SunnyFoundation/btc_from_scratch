from io import BytesIO
import time

from helper import (
    encode_varint,
    hash256,
    int_to_little_endian,
    little_endian_to_int,
    read_varint,
    decode_base58,
    hash160,
    target_to_bits,
    bits_to_target,
    merkle_root,
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
        self.merkle_root_hash = merkle_root_bytes
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
        merkle_root_bytes = self.merkle_root_hash[::-1]
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
        return root[::-1] == self.merkle_root_hash


# raw_data_hex = "0100000082fdb159898218402baae8290308fc00cac9c13944f2913a426608000000000027587a10248001f424ad94bb55cd6cd6086a0e05767173bdbdf647187beca76cb385d54c6332151b54f01d91"
# raw_data_bytes = bytes.fromhex(raw_data_hex)

# stream = BytesIO(raw_data_bytes)
# # block = Block.parse(stream)

# block1_hex = "000000203471101bbda3fe307664b3283a9ef0e97d9a38a7eacd8800000000000000000010c8aba8479bbaa5e0848152fd3c2289ca50e1c3e58c9a4faaafbdf5803c5448ddb845597e8b0118e43a81d3"


# block2_hex = "02000020f1472d9db4b563c35f97c428ac903f23b7fc055d1cfc26000000000000000000b3f449fcbe1bc4cfbcb8283a0d2c037f961a3fdf2b8bedc144973735eea707e1264258597e8b0118e5f00474"


# first_block = Block.parse(BytesIO(bytes.fromhex(block1_hex)))  # 471744
# last_block = Block.parse(BytesIO(bytes.fromhex(block2_hex)))  # 473759
# time_differential = last_block.timestamp - first_block.timestamp


# new_bits = calculate_new_bits(last_block.bits, time_differential)
# print(new_bits.hex())  # 473760의 새로운 bits 값 : 308d0118


version = 1
prev_block = b"\x00" * 32
merkle_root_example = bytes.fromhex(
    "f3e9e13b86a3436217645a205a2e36127435fce46da0d85915d3a95c3a3733a1"
)
timestamp = int(time.time())
# bits = b"\xff\xff\x0f\x1e"  # A low difficulty for quick testing
bits = b"\xff\xff\x07\x1e"
# bits = b"\xff\xff\x00\x1d"
nonce = b"\x00\x00\x00\x00"  # Will be found by the miner


# block = Block(version, prev_block, merkle_root, timestamp, bits, nonce)
# found_nonce = block.mine()
# is_valid = block.check_pow()
# print(is_valid)


# MERKLE ROOT
# hashes_hex = [
#     "f54cb69e5dc1bd38ee6901e4ec2007a5030e14bdd60afb4d2f3428c88eea17c1",
#     "c57c2d678da0a7ee8cfa058f1cf49bfcb00ae21eda966640e312b464414731c1",
#     "b027077c94668a84a5d0e72ac0020bae3838cb7f9ee3fa4e81d1eecf6eda91f3",
#     "8131a1b8ec3a815b4800b43dff6c6963c75193c4190ec946b93245a9928a233d",
#     "ae7d63ffcb3ae2bc0681eca0df10dda3ca36dedb9dbf49e33c5fbe33262f0910",
#     "61a14b1bbdcdda8a22e61036839e8b110913832efd4b086948a6a64fd5b3377d",
#     "fc7051c8b536ac87344c5497595d5d2ffdaba471c73fae15fe9228547ea71881",
#     "77386a46e26f69b3cd435aa4faac932027f58d0b7252e62fb6c9c2489887f6df",
#     "59cbc055ccd26a2c4c4df2770382c7fea135c56d9e75d3f758ac465f74c025b8",
#     "7c2bf5687f19785a61be9f46e031ba041c7f93e2b7e9212799d84ba052395195",
#     "08598eebd94c18b0d59ac921e9ba99e2b8ab7d9fccde7d44f2bd4d5e2e726d2e",
#     "f0bb99ef46b029dd6f714e4b12a7d796258c48fee57324ebdc0bbc4700753ab1",
# ]


# hashes = [bytes.fromhex(x) for x in hashes_hex]


# stream = BytesIO(
#     bytes.fromhex(
#         "00000020fcb19f7895db08cadc9573e7915e3919fb76d59868a51d995201000000000000acbcab8bcc1af95d8d563b77d24c3d19b18f1486383d75a5085c4e86c86beed691cfa85916ca061a00000000"
#     )
# )


# block = Block.parse(stream)
# block.tx_hashes = hashes
# print(block.validate_merkle_root())
