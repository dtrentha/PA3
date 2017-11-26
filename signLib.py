#!/usr/bin/enc python3

import binascii
import os
import operator
import sys
import argparse
from Crypto.Cipher import AES
from multiprocessing import Pool
import cryptoLib as CL
import rsaLib as RL
import struct
from Crypto.Util import number
import random
from Crypto.Hash import SHA256


def rsaSign(h,n,d):

    m = int(h, 16)
    sig = RL.powMod(m,d,n)
    return str(sig)

def rsaVal(m,s,n,e):

    val = str(s**e)
    print(val)
    mess = str(int(m, 16))
    h = SHA256.new()
    h.update(mess)
    h = h.hexdigest()
    h = int(h, 16)
    print(h % n)






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
            mF = open(args.m, 'rb')
            buf = mF.read()
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
            h = SHA256.new()
            h.update(buf)
            h = h.hexdigest()

        if args.s != None:
            sF = open(args.s, 'r')
            line = sF.readline()
            sF.close()
            sig = int(line)


        print(rsaVal(h,sig,n,e))
        return


if __name__ == '__main__':
	main()







