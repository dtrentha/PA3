#!/usr/bin/enc python3

import binascii
import os
import operator
import sys
import argparse
import cryptoLib as CL
from Crypto.Cipher import AES
import struct
from Crypto.Util import number
from Crypto.Hash import SHA256

def mac_tag(message, length, key):
    ciblocks = []
    blocks = CL.blockify(message)
    blocks = CL.padify(blocks)
    newiv = length
    for i in blocks:
        ciblock = CL.xorify(i,newiv)
        ciphertext = CL.encrypt(key,ciblock)
        ciblocks.append(ciphertext)
        ciphertext = binascii.unhexlify(ciphertext)
        newiv = ciphertext

    return ciblocks[-1]


def main():
    blocks = []

    parser = argparse.ArgumentParser()
    parser.add_argument('mode')
    parser.add_argument('-k')
    parser.add_argument('-m')
    parser.add_argument('-t')

    args = parser.parse_args()

    mode = args.mode

    kfile = open(args.k)
    key = kfile.readline()
    key = key.rstrip('\n')
    key = binascii.unhexlify(key)

    if args.m != None:
        mF = open(args.m, 'rb')
        message = bytes('', encoding = 'utf-8')
        for line in mF:
            message += line


    if mode == "cbcmac-tag":
        tF = open(args.t, 'w')
        iv = format(len(message), '016b')
        iv = CL.encrypt(key,iv)
        iv = binascii.unhexlify(iv)
        tag = mac_tag(message,iv,key)
        tF.write("%s\n" % tag)

    if mode == "cbcmac-validate":
        tF = open(args.t, 'r')
        tag = tF.readline()
        tag = tag.rstrip('\n')
        iv = format(len(message), '016b')
        iv = CL.encrypt(key,iv)
        iv = binascii.unhexlify(iv)
        check_tag = mac_tag(message, iv, key)
        if check_tag == tag:
            return True
        else:
            return False

if __name__ == "__main__":
	main()
