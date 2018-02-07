#!/usr/bin/env python
# -*- coding: utf-8 -*-


POW = 26


def encrypt_letter(key, let):
    min = ord('A') if let.isupper() else ord('a')
    num = ord(let) - min

    return chr((num + key) % POW + min)


def decrypt_letter(key, let):
    min = ord('A') if let.isupper() else ord('a')
    num = ord(let) - min

    return chr((num - key + POW) % POW + min)


def encrypt(key, text):
    enc_genexp = (
        encrypt_letter(key, let) if let.isalpha() else let for let in text
    )
    return ''.join(enc_genexp)


def decrypt(key, text):
    dec_genexp = (
        decrypt_letter(key, let) if let.isalpha() else let for let in text
    )
    return ''.join(dec_genexp)


def main():
    key = int(raw_input("Key: "))

    with open('input.txt') as fp:
        text = fp.read()
        print(text)

        encr = encrypt(key, text)
        print("Encrypted: {}".format(encr))

        decr = decrypt(key, encr)
        print("Decrypted: {}".format(decr))


if __name__ == '__main__':
    main()
