#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bitarray import bitarray
from common import (
    map_bits, left_shift, bitarray_to_int,
    int_to_bitarray, bytes_to_bitarray,
    space_complete
)
from constants import (
    __ip, __pc1, __pc2, __sbox,
    __left_rotations, __expansion_table, __p, __fp,
    TYPE, CHUNK_BIT_SIZE, CHUNK_HALF_BIT_SIZE,
    CHUNK_S_BOX, STRING_SIZE, ITERS
)


def split_chunks(message, size):
    for i in range(0, len(message), size):
        yield message[i: i + size]


def ip_permutation(chunk):
    return map_bits(chunk, __ip)


def clean_key(key):
    return map_bits(key, __pc1)


def shift_key(bitarr, iter):
    length = len(bitarr)
    half = int(length / 2)
    left_shift(bitarr, 0, half, __left_rotations[iter])
    left_shift(bitarr, half, length, __left_rotations[iter])


def iter_key(key):
    _key = clean_key(key)
    for i in range(ITERS):
        shift_key(_key, i)
        yield map_bits(_key, __pc2)


def extension_E(chunk):
    return map_bits(chunk, __expansion_table)


def func(right_chunk, key):
    ext = extension_E(right_chunk)
    ext = ext ^ key

    i = 0
    res = bitarray()
    for chunk in split_chunks(ext, CHUNK_S_BOX):
        string = bitarray_to_int(chunk[0::CHUNK_S_BOX - 1])
        column = bitarray_to_int(chunk[1:CHUNK_S_BOX-1])

        s_box = int_to_bitarray(
            __sbox[i][string*STRING_SIZE + column])
        res = res + s_box
        i += 1

    return map_bits(res, __p)


def crypt_chunk(chunk, key, crypt_type):
    key_range = list(iter_key(key))
    if crypt_type == TYPE["decrypt"]:
        key_range = reversed(key_range)

    chunk = ip_permutation(chunk)
    for key in key_range:
        right_old = chunk[CHUNK_HALF_BIT_SIZE:]
        left_old = chunk[:CHUNK_HALF_BIT_SIZE]
        right_new = func(right_old, key) ^ left_old
        left_new = right_old

        chunk[CHUNK_HALF_BIT_SIZE:] = right_new
        chunk[:CHUNK_HALF_BIT_SIZE] = left_new

    chunk[CHUNK_HALF_BIT_SIZE:] = left_new
    chunk[:CHUNK_HALF_BIT_SIZE] = right_new
    chunk = map_bits(chunk, __fp)

    return chunk


def crypt(message, key, crypt_type):
    _msg = (space_complete(message)
            if crypt_type == TYPE["encrypt"] else message)
    msg_bitarr = bytes_to_bitarray(_msg)
    key_bitarr = bytes_to_bitarray(key)

    crypted_chunks = (
        crypt_chunk(chunk, key_bitarr, crypt_type)
        for chunk in split_chunks(msg_bitarr, CHUNK_BIT_SIZE))

    return b"".join(chunk.tobytes() for chunk in crypted_chunks)


def main():
    message = b"1234567812345678hj"
    key = b"12345678"
    encoded = crypt(message, key, TYPE["encrypt"])
    decoded = crypt(encoded, key, TYPE["decrypt"])

    print("Message: " + str(message))
    print("Encoded: " + str(encoded))
    print("Decoded: " + str(decoded))


if __name__ == '__main__':
    main()
