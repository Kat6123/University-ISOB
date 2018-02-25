#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from bitarray import bitarray


def bitarray_to_int(bitarr):
    return int(bitarr.to01(), 2)


def int_to_bitarray(integer, bitarray_size=4):
    bitarr = bitarray("0"*bitarray_size)
    bin_int = bin(integer)[2:]
    bitarr[bitarray_size-len(bin_int):] = bitarray(bin_int)
    return bitarr


def bytes_to_bitarray(byte):
    bitarr = bitarray()
    bitarr.frombytes(byte)
    return bitarr


def left_shift(bitarr, start, end, shift):
    bitarr[start:end] = bitarr[start+shift:end] + bitarr[start:start+shift]


def right_shift(bitarr, start, end, shift):
    bitarr[start:end] = bitarr[end-shift:end] + bitarr[start:end-shift]


def map_bits(bitarr, bitmap):
    return bitarray(bitarr[_] for _ in bitmap)
