import hashlib

from Ecc import S256Point, Signature


from helper import (
    hash160,
    hash256,
)


def op_verify(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    if decode_num(element) == 0:
        return False
    return True


def op_equal(stack):
    if len(stack) < 2:
        return False
    element1 = stack.pop()
    element2 = stack.pop()

    if element1 == element2:
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def op_equalverify(stack):
    return op_equal(stack) and op_verify(stack)


def op_dup(stack):
    if len(stack) < 1:
        return False
    stack.append(stack[-1])
    return True


def op_sha256(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    stack.append(hashlib.sha256(element).digest())
    return True


def op_hash160(stack):
    if len(stack) < 1:
        return False
    element = stack.pop()
    h160 = hash160(element)
    stack.append(h160)
    return True



def op_checkmultisig(stack, z):
    if len(stack) < 1:
        return False
    n = decode_num(stack.pop())
    if len(stack) < n + 1:
        return False
    sec_pubkeys = []
    for _ in range(n):
        sec_pubkeys.append(stack.pop())
    m = decode_num(stack.pop())
    if len(stack) < m + 1:
        return False
    der_signatures = []
    for _ in range(m):
        der_signatures.append(stack.pop()[:-1])
    stack.pop()
    try:
        points = [S256Point.parse(sec) for sec in sec_pubkeys]
        sigs = [Signature.parse(der) for der in der_signatures]
        for sig in sigs:
            if len(points) == 0:
                return False
            while points:
                point = points.pop(0)
                if point.verify(z, sig):
                    break
        stack.append(encode_num(1))
    except (ValueError, SyntaxError):
        return False
    return True


def op_checksig(stack, z):
    if len(stack) < 2:
        return False
    sec_pubkey = stack.pop()
    der_signature = stack.pop()[:-1]
    try:
        point = S256Point.parse(sec_pubkey)
        sig = Signature.parse(der_signature)
    except (ValueError, SyntaxError) as e:
        return False
    if point.verify(z, sig):
        stack.append(encode_num(1))
    else:
        stack.append(encode_num(0))
    return True


def encode_num(num):
    if num == 0:
        return b""
    abs_num = abs(num)
    negative = num < 0
    result = bytearray()
    while abs_num:
        result.append(abs_num & 0xFF)
        abs_num >>= 8
    if result[-1] & 0x80:
        if negative:
            result.append(0x80)
        else:
            result.append(0)
    elif negative:
        result[-1] |= 0x80
    return bytes(result)


def decode_num(element):
    if element == b"":
        return 0
    big_endian = element[::-1]
    if big_endian[0] & 0x80:
        negative = True
        result = big_endian[0] & 0x7F
    else:
        negative = False
        result = big_endian[0]
    for c in big_endian[1:]:
        result <<= 8
        result += c
    if negative:
        return -result
    else:
        return result


OP_CODE_FUNCTIONS = {
    118: op_dup,
    136: op_equalverify,
    168: op_sha256,
    169: op_hash160,
    172: op_checksig,
}


OP_CODE_NAMES = {
    76: "OP_PUSHDATA1",
    77: "OP_PUSHDATA2",
    118: "OP_DUP",
    136: "OP_EQUALVERIFY",
    168: "OP_SHA256",
    169: "OP_HASH160",
    172: "OP_CHECKSIG",
}
