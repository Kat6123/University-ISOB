#!/usr/bin/env python3
# -*- coding: utf-8 -*-


from bitarray import bitarray
from tables import (
    __ip, __pc1, __pc2, __sbox, __left_rotations, __expansion_table, __p, __fp)


TYPE = {
    "encrypt": 1,
    "decrypt": 0
}

CHUNK_BIT_SIZE = 64
CHUNK_HALF_BIT_SIZE = 32
CHUNK_S_BOX = 6
CODING = "utf-8"
ITERS = 16
STRING_SIZE = 16


def _chunks(message, size):
    for i in range(0, len(message), size):
        yield message[i: i + size]


def map_bits(bitarr, bitmap):
    return bitarray(bitarr[_] for _ in bitmap)


def ip_permutation(chunk):
    return map_bits(chunk, __ip)


def clean_key(key):
    return map_bits(key, __pc1)


def left_shift(bitarr, start, end, shift):
    bitarr[start:end] = bitarr[start+shift:end] + bitarr[start:start+shift]


def right_shift(bitarr, start, end, shift):
    bitarr[start:end] = bitarr[end-shift:end] + bitarr[start:end-shift]


def shift_key(bitarr, iter):
    length = len(bitarr)
    half = int(length / 2)
    left_shift(bitarr, 0, half, __left_rotations[iter])
    left_shift(bitarr, half, length, __left_rotations[iter])


def iter_key(key):
    _key = clean_key(key)
    for i in range(ITERS):
        shift_key(_key, i)

        yield map_bits(key, __pc2)


def extension_E(chunk):
    return map_bits(chunk, __expansion_table)


def bitarray_to_int(bitarr):
    return int(bitarr.to01(), 2)


def int_to_bitarray(integer, bitarray_size=4):
    bitarr = bitarray("0"*bitarray_size)
    bin_int = bin(integer)[2:]
    bitarr[bitarray_size-len(bin_int):] = bitarray(bin_int)
    return bitarr


def func(right_chunk, key):
    ext = extension_E(right_chunk)
    ext = ext ^ key

    i = 0
    res = bitarray()
    for chunk in _chunks(ext, CHUNK_S_BOX):
        string = bitarray_to_int(chunk[0::CHUNK_S_BOX - 1])
        column = bitarray_to_int(chunk[1:CHUNK_S_BOX-1])

        s_box = int_to_bitarray(
            __sbox[i][string*STRING_SIZE + column])
        res = res + s_box
        i += 1

    return map_bits(res, __p)


def crypt_chunk(chunk, key):
    chunk = ip_permutation(chunk)
    for key in iter_key(key):
        right_old = chunk[CHUNK_HALF_BIT_SIZE:]
        left_old = chunk[:CHUNK_HALF_BIT_SIZE]
        right_new = func(right_old, key) ^ left_old
        left_new = right_old

        chunk[CHUNK_HALF_BIT_SIZE:] = right_new
        chunk[:CHUNK_HALF_BIT_SIZE] = left_new

    chunk = map_bits(chunk, __fp)

    return chunk


def decrypt_chunk(chunk, key):
    chunk = ip_permutation(chunk)
    for key in iter_key(key):
        right_old = chunk[CHUNK_HALF_BIT_SIZE:]
        left_old = chunk[:CHUNK_HALF_BIT_SIZE]
        right_new = left_old
        left_new = func(left_old, key) ^ right_old

        chunk[CHUNK_HALF_BIT_SIZE:] = right_new
        chunk[:CHUNK_HALF_BIT_SIZE] = left_new

    chunk = map_bits(chunk, __fp)

    return chunk


def crypt(message, key, crypt_type):
    # TODO: generate key from type
    # TODO:  Check if chunk is less than 64 bit ->
    # first number size of  extra bits
    # if crypt_type == TYPE["encrypt"]:
    # TODO: check utf-8
    _message = bitarray()
    _message.frombytes(message)
    if crypt_type == TYPE["encrypt"]:
        crypted_chunks = (
            crypt_chunk(chunk, key).tobytes()
            for chunk in _chunks(_message, CHUNK_BIT_SIZE))
    else:
        crypted_chunks = (
            decrypt_chunk(chunk, key).tobytes()
            for chunk in _chunks(_message, CHUNK_BIT_SIZE))
    res = b''
    for _ in crypted_chunks:
        res = res + _
    # XXX: join not work
    # return b''.join(chunk for chunk in crypted_chunks)
    return res


def main():
    message = b"Hi! there jsdhfljghld lshflsdhfs dflsifhsifhdilf ghslifg"
    key = bitarray()
    key.frombytes(b"12345678")
    encoded = crypt(message, key, TYPE["encrypt"])
    decoded = crypt(message, key, TYPE["decrypt"])
    print(b"Message: " + message)
    print(b"Encoded: " + encoded)
    print(b"Decoded: " + decoded.decode("utf-8"))


if __name__ == '__main__':
    main()
