#!/usr/bin/env python3

import random
import sys
import argparse
import os
import struct
from Crypto.Util import number
import binascii
import rsaLib as RL
import signLib as SL
from Crypto.Hash import SHA256


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('func')
    parser.add_argument('-p')
    parser.add_argument('-s')
    parser.add_argument('-n')
    parser.add_argument('-c',nargs = '?')

    args = parser.parse_args()

    func = args.func

    if func == "rsa-keygen":
        if args.p != None:
            pF = open(args.p, 'w')
        if args.s != None:
            sF = open(args.s, 'w')
        if args.n != None:
            bits = int(args.n)

        n, e, d = RL.rsaKeyGen(bits)

        pF.write(str(bits) + '\n')
        pF.write(str(n) + '\n')
        pF.write(str(e) + '\n')
        pF.close()

        sF.write(str(bits) + '\n')
        sF.write(str(n) + '\n')
        sF.write(str(d) + '\n')
        sF.close()

        if args.c != None:
            caF = open(args.c, 'r')
            lines = caF.readlines()
            caF.close()
            bits = int(lines[0])
            n = int(lines[1])
            d = int(lines[2])

        newpubF = args.p + "-casig"
        pubF = open(args.p, 'r')
        buf = pubF.read()
        buf = buf.encode('utf-8')
        h = SHA256.new()
        h.update(buf)
        h = h.hexdigest()
        pubF.close()

        tp = SL.rsaSign(h,n,d)

        cF = open(newpubF, 'w')
        cF.write(tp)
        cF.close()
        return



if __name__ == '__main__':
    main()
