#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import bitarray

TYPE = {
    "encrypt": 1,
    "decrypt": 0
}


def crypt(message, key, type):
    # TODO: generate key from type


def main(arg):
    message = "Hi! there jsdhfljghld lshflsdhfs dflsifhsifhdilf ghslifghdfih"
    encoded = crypt(message, "secret key", TYPE["encrypt"])
    decoded = crypt(message, "secret key", TYPE["decrypt"])


if __name__ == '__main__':
    main()
