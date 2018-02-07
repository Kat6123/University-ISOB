#!/usr/bin/env python
# -*- coding: utf-8 -*-
from cezar import encrypt_letter, decrypt_letter


def encrypt(key_text, text):
    enc_list = [
        ord(k) - ord('A') if k.isupper()
        else ord(k) - ord('a') for k in key_text]

    return ''.join(
        encrypt_letter(key, t_l) if t_l.isalpha()
        else t_l for key, t_l in zip(enc_list, text))


def decrypt(key_text, text):
    enc_list = [
        ord(k) - ord('A') if k.isupper()
        else ord(k) - ord('a') for k in key_text]

    return ''.join(
        decrypt_letter(key, t_l) if t_l.isalpha()
        else t_l for key, t_l in zip(enc_list, text))


def main():
    key = raw_input("Input key word: ")

    with open('input.txt') as fp:
        text = fp.read()
        print(text)

        d, m = divmod(len(text), len(key))
        key_text = ''.join(key for _ in xrange(d)) + key[:m]

        encrypted = encrypt(key_text, text)
        print(encrypted)
        decrypted = decrypt(key_text, encrypted)
        print(decrypted)


if __name__ == '__main__':
    main()
