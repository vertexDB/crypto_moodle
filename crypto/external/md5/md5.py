# taken from https://github.com/qalle2/md5-algo
# an MD5 implementation; see http://en.wikipedia.org/wiki/MD5

import math, struct

def pad_message(message):
    # append terminator byte, padding and original length in bits modulo
    # 2 ** 64; the new length will be a multiple of 64 bytes (512 bits)
    padLen = (64 - 1 - 8 - len(message) % 64) % 64
    lenBits = (len(message) * 8) % 2 ** 64
    return message + b"\x80" + padLen * b"\x00" + struct.pack("<Q", lenBits)

def rotate_left(n, bits):
    # rotate a 32-bit integer left
    return ((n << bits) & 0xffff_ffff) | (n >> (32 - bits))

def hash_chunk(state, chunk):
    # hash one chunk
    # state:   4 * 32 = 128 bits
    # chunk:  16 * 32 = 512 bits
    # return:  4 * 32 = 128 bits

    (a, b, c, d) = state

    for r in range(64):
        if r < 16:
            bits = d ^ (b & (c ^ d))  # = (b & c) | (~b & d)
            index = r
            shift = (7, 12, 17, 22)[r & 3]
        elif r < 32:
            bits = c ^ (d & (b ^ c))  # = (b & d) | (c & ~d)
            index = (5 * r + 1) & 15
            shift = (5, 9, 14, 20)[r & 3]
        elif r < 48:
            bits = b ^ c ^ d
            index = (3 * r + 5) & 15
            shift = (4, 11, 16, 23)[r & 3]
        else:
            bits = c ^ (b | ~d)
            index = (7 * r) & 15
            shift = (6, 10, 15, 21)[r & 3]

        const = math.floor(abs(math.sin(r + 1)) * 0x1_0000_0000)
        bAdd = (const + a + bits + chunk[index]) & 0xffff_ffff
        bAdd = rotate_left(bAdd, shift)
        (a, b, c, d) = (d, (b + bAdd) & 0xffff_ffff, b, c)

    return (a, b, c, d)

def md5(message):
    # hash a bytestring; return the hash as 16 bytes

    # initialize state of algorithm (4 * 32 bits = 128 bits)
    state = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476]

    # pad message to a multiple of 512 bits
    message = pad_message(message)

    # add the hash of each 512-bit (16 * 32-bit) chunk to the state
    for chunk in struct.iter_unpack("<16I", message):
        hash_ = hash_chunk(state, chunk)
        state = [(s + h) & 0xffff_ffff for (s, h) in zip(state, hash_)]

    # final state = hash of entire message
    return struct.pack("<4I", *state)
