#!/usr/bin/enc python3

import binascii
import os
import operator
import sys
import argparse
import rsaLib as RL
import struct
from Crypto.Util import number
import random
from Crypto.Hash import SHA256


def rsaSign(h,n,d):
    h = int(h, 16)
    sig = RL.powMod(h,d,n)
    return str(sig)

def rsaVal(m,sig,n,e):

    m = int(m, 16)
    ver = RL.powMod(sig,e,n)

    if m == ver:
        return True
    else:
        return False


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('func')
    parser.add_argument('-k')
    parser.add_argument('-m')
    parser.add_argument('-s')

    args = parser.parse_args()

    func = args.func

    if func == "rsa-sign":
        if args.k != None:
            kF = open(args.k, 'r')
            lines = kF.readlines()
            kF.close()
            bits = int(lines[0])
            n = int(lines[1])
            d = int(lines[2])

        if args.m != None:
            mF = open(args.m, 'r')
            buf = mF.read()
            buf = buf.encode('utf-8')
            h = SHA256.new()
            h.update(buf)
            h = h.hexdigest()


        if args.s != None:
            sF = open(args.s, 'w')

        sF.write(rsaSign(h,n,d))
        sF.close()
        return

    if func == "rsa-validate":
        if args.k != None:
            kF = open(args.k, 'r')
            lines = kF.readlines()
            kF.close()
            bits = int(lines[0])
            n = int(lines[1])
            e = int(lines[2])

        if args.m != None:
            mF = open(args.m, 'r')
            buf = mF.read()
            buf = buf.encode('utf-8')
            h = SHA256.new()
            h.update(buf)
            h = h.hexdigest()

        if args.s != None:
            sF = open(args.s, 'r')
            line = sF.readline()
            sF.close()
            sig = int(line)


        result = rsaVal(h,sig,n,e)
        return result


if __name__ == '__main__':
	main()







