import hashlib


SIGHASH_ALL = 1


def h160_to_p2pkh_address(h160, testnet=False):
    if testnet:
        prefix = b"\x6f"
    else:
        prefix = b"\x00"
    return encode_base58_checksum(prefix + h160)


def h160_to_p2sh_address(h160, testnet=False):
    if testnet:
        prefix = b"\xc4"
    else:
        prefix = b"\x05"
    return encode_base58_checksum(prefix + h160)


def hash256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()


def hash160(s):
    return hashlib.new("ripemd160", hashlib.sha256(s).digest()).digest()  # <1>


BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
TWO_WEEKS = 60 * 60 * 24 * 14


def encode_base58(s):
    count = 0
    for c in s:  # <1>
        if c == 0:
            count += 1
        else:
            break
    num = int.from_bytes(s, "big")
    prefix = "1" * count
    result = ""
    while num > 0:  # <2>
        num, mod = divmod(num, 58)
        result = BASE58_ALPHABET[mod] + result
    return prefix + result  # <3>


def encode_base58_checksum(b):
    return encode_base58(b + hash256(b)[:4])


def decode_base58(s):
    num = 0
    for c in s:
        num *= 58
        num += BASE58_ALPHABET.index(c)
    combined = num.to_bytes(25, byteorder="big")
    checksum = combined[-4:]
    if hash256(combined[:-4])[:4] != checksum:
        raise ValueError(
            "bad address: {} {}".format(checksum, hash256(combined[:-4])[:4])
        )
    return combined[1:-4]  # 첫 바이트 , 체크섬 빼고 공개키를 바이트화 시키는것


def little_endian_to_int(b):
    return int.from_bytes(b, "little")


def int_to_little_endian(n, length):
    return n.to_bytes(length, "little")


def read_varint(s):
    """read_varint reads a variable integer from a stream"""
    i = s.read(1)[0]
    if i == 0xFD:
        # 0xfd means the next two bytes are the number
        return little_endian_to_int(s.read(2))
    elif i == 0xFE:
        # 0xfe means the next four bytes are the number
        return little_endian_to_int(s.read(4))
    elif i == 0xFF:
        # 0xff means the next eight bytes are the number
        return little_endian_to_int(s.read(8))
    else:
        # anything else is just the integer
        return i


def encode_varint(i):
    """encodes an integer as a varint"""
    if i < 0xFD:
        return bytes([i])
    elif i < 0x10000:
        return b"\xfd" + int_to_little_endian(i, 2)
    elif i < 0x100000000:
        return b"\xfe" + int_to_little_endian(i, 4)
    elif i < 0x10000000000000000:
        return b"\xff" + int_to_little_endian(i, 8)
    else:
        raise ValueError("integer too large: {}".format(i))


def bits_to_target(bits):
    exponent = bits[-1]
    coefficient = little_endian_to_int(bits[:-1])
    return coefficient * 256 ** (exponent - 3)


def target_to_bits(target):
    raw_bytes = target.to_bytes(32, "big")
    raw_bytes = raw_bytes.lstrip(b"\x00")
    if raw_bytes[0] > 0x7F:
        exponent = len(raw_bytes) + 1
        coefficient = b"\x00" + raw_bytes[:2]
    else:
        exponent = len(raw_bytes)
        coefficient = raw_bytes[:3]
    new_bits = coefficient[::-1] + bytes([exponent])
    return new_bits


def merkle_parent(hash1, hash2):
    """Takes the binary hashes and calculates the hash256"""
    return hash256(hash1 + hash2)


def merkle_parent_level(hashes):
    """Takes a list of binary hashes and returns a list that's half
    the length"""
    if len(hashes) == 1:
        raise RuntimeError("Cannot take a parent level with only 1 item")
    if len(hashes) % 2 == 1:
        hashes.append(hashes[-1])
    parent_level = []
    for i in range(0, len(hashes), 2):
        parent = merkle_parent(hashes[i], hashes[i + 1])
        parent_level.append(parent)
    return parent_level


def merkle_root(hashes):
    """Takes a list of binary hashes and returns the merkle root"""
    current_level = hashes
    while len(current_level) > 1:
        current_level = merkle_parent_level(current_level)
    return current_level[0]


def bit_field_to_bytes(bit_field):
    if len(bit_field) % 8 != 0:
        raise RuntimeError("bit_field does not have a length that is divisible by 8")
    result = bytearray(len(bit_field) // 8)
    for i, bit in enumerate(bit_field):
        byte_index, bit_index = divmod(i, 8)
        if bit:
            result[byte_index] |= 1 << bit_index
    return bytes(result)


# tag::source1[]
def bytes_to_bit_field(some_bytes):
    flag_bits = []
    for byte in some_bytes:
        for _ in range(8):
            flag_bits.append(byte & 1)
            byte >>= 1
    return flag_bits


# Base58
# sec = "02933ec2d2b111b92737ec12f1c5d20f3233a0ad21cd8b36d0bca7a0cfa5cb8701"
# sec_to_bytes = bytes.fromhex(sec)
# print(encode_base58(sec_to_bytes))  mNRBP9AM1HtBoBxWcT6qU51HFc887Q3DDGrc8nWQwPUC
# print(encode_base58_checksum(sec_to_bytes))   61LXuQFciEDZnZB9EdA5NPAHbm6f7iFQbrHioRfgi4YNkdZP6Q
