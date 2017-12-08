#!/user/bin/enc python3

import binascii
import os
import operator
import sys
import argparse
import rsaGen as RG
import signLib as SL
import macLib as ML
import rsaLib as RL
import cryptoLib as CL
import struct
from Crypto.Util import number
import random
from Crypto.Hash import SHA256

def symKey(pn, pe, sn, sd, bits,directory):

    keyPath = os.path.join(directory,"SymKeyMan")
    signPath = os.path.join(directory, "SymKeyManSigned")

    key = os.urandom(16)

    aesKey = str(int.from_bytes(key, byteorder='big', signed = False))
    sK = open(keyPath, 'w')

    sK.write(str(RL.rsaEncrypt(aesKey,pe,pn,bits)) + '\n')
    sK.close()

    sKey = open(keyPath, 'r')
    buf = sKey.read()
    buf = buf.encode('utf-8')
    h = SHA256.new()
    h.update(buf)
    h = h.hexdigest()

    symSigF = open(signPath, 'w')

    symSigF.write(SL.rsaSign(h,sn,sd))
    symSigF.close()
    #print('print', key)
    return key

def cleanup(directory, n, e):

    keyPath = os.path.join(directory,"SymKeyMan")
    signPath = os.path.join(directory, "SymKeyManSigned")

    skmsig = open(signPath, 'r')
    line = skmsig.readline()
    skmsig.close()
    sSig = int(line)

    skmF = open(keyPath, 'r')
    buf = skmF.read()
    buf = buf.encode('utf-8')
    skmh = SHA256.new()
    skmh.update(buf)
    skmh = skmh.hexdigest()

    if SL.rsaVal(skmh,sSig,n, e) == False:
        print("symmetric key manifest invalid, abort")
        return False
    else:
        print(True)
        return True


def findKey(sn,sd,bits,directory):

    keyPath = os.path.join(directory, "SymKeyMan")
    signPath = os.path.join(directory, "SymKeyManSigned")
    kF = open(keyPath, 'r')
    ekey = int(kF.readline())
    kF.close()

    key = RL.rsaDecrypt(ekey,sd,sn, bits)
    key = int(key)
    key = key.to_bytes(16,byteorder ='big', signed = False)
    #print('print',key)
    os.remove(keyPath)
    os.remove(signPath)
    return key

def encryptDir(directory,key):

    km = "SymKeyMan"
    kmt= "SymKeyManSigned"

    listing = os.listdir(directory)
    for infile in listing:
        if infile != km and infile != kmt:
            path = os.path.join(directory,infile)
            iF = open(path,'rb')
            encFile = infile + '-locked'
            message = bytes('', encoding='utf-8')
            for line in iF:
                message += line

            iv = CL.genIV()

            blocks = CL.cbc_enc(message, iv, key)
            pathOut = os.path.join(directory, encFile)
            oF = open(pathOut, 'w')

            for i in blocks:
                oF.write("%s\n" % i)

    return

def decryptDir(directory, key):

    l = '-locked'
    listing = os.listdir(directory)
    for infile in listing:
        path = os.path.join(directory,infile)
        lk = path[-7:]
        unlk = path[:-7]
        if lk == l:
            iF = open(path, 'r')
            oF = open(unlk, 'wb')
            blocks = iF.readlines()
            for i in range(len(blocks)):
                blocks[i] = blocks[i].strip('\n')
            message = CL.cbc_dec(blocks, key)
            oF.write(message)
            os.remove(path)
    return



def delFiles(directory):

    lock = '-locked'
    km = os.path.join(directory,"SymKeyMan")
    kmt = os.path.join(directory,"SymKeyManSigned")
    listing = os.listdir(directory)
    for infile in listing:
        path = os.path.join(directory,infile)
        if path[-7:] != lock and path != km and path !=kmt:
            os.remove(path)

    return

def macFile(directory, key):

    km = "SymKeyMan"
    kmt = "SymKeyManSigned"
    listing = os.listdir(directory)
    for infile in listing:
        if infile != km and infile != kmt:
            path = os.path.join(directory,infile)
            tagOut = path + '-tag'
            mF = open(path, 'rb')
            message = bytes('', encoding='utf-8')
            for line in mF:
                message += line
            iv = format(len(message), '016b')
            iv = CL.encrypt(key,iv)
            iv = binascii.unhexlify(iv)
            tag = ML.mac_tag(message, iv, key)
            tF = open(tagOut, 'w')
            tF.write("%s\n" % tag)

    return

def valMacs(directory, key):

    t = "-tag"
    listing = os.listdir(directory)
    for infile in listing:
        path = os.path.join(directory,infile)
        if path[-4:] != t:
            oF = open(path, 'rb')
            message = bytes('', encoding = 'utf-8')
            for line in oF:
                message += line

            tagFile = path + t
            tF = open(tagFile, 'r')
            tag = tF.readline()
            tag = tag.rstrip('\n')
            iv = format(len(message), '016b')
            iv = CL.encrypt(key,iv)
            iv = binascii.unhexlify(iv)
            check_tag = ML.mac_tag(message, iv, key)
            if check_tag == tag:
                print(True)
            else:
                return False

            os.remove(tagFile)

    return True

def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('mode')
    parser.add_argument('-d')
    parser.add_argument('-p')
    parser.add_argument('-r')
    parser.add_argument('-vk')

    args = parser.parse_args()

    mode = args.mode

    tD = args.d

    if args.p != None:
        aPK = open(args.p, 'r')
        lines = aPK.readlines()
        aPK.close()
        bits = int(lines[0])
        aPubN = int(lines[1])
        aPubE = int(lines[2])

    if args.r != None:
        aSK = open(args.r, 'r')
        lines = aSK.readlines()
        aSK.close()
        aPriN = int(lines[1])
        aPriD = int(lines[2])

    if args.vk != None:
        vPK = open(args.vk, 'r')
        lines = vPK.readlines()
        vPK.close()
        vPubN = int(lines[1])
        vPubE = int(lines[2])

    if mode == "lock":

        sigFile = args.p + "-casig"
        sF = open(sigFile, 'r')
        line = sF.readline()
        sF.close()
        sig = int(line)

        hF = open(args.p, 'r')
        buf = hF.read()
        buf = buf.encode('utf-8')
        h = SHA256.new()
        h.update(buf)
        h = h.hexdigest()

        if SL.rsaVal(h,sig,vPubN, vPubE) == False:
            print("unlocking public key invalid, abort")
            return
        else:
            print(True)

        key = symKey(aPubN,aPubE,aPriN,aPriD,bits,tD)

        encryptDir(tD, key)

        delFiles(tD)

        macFile(tD, key)

    if mode == "unlock":

        sigFile = args.p + "-casig"
        sF = open(sigFile, 'r')
        line = sF.readline()
        sF.close()
        sig = int(line)

        hF = open(args.p, 'r')
        buf = hF.read()
        buf = buf.encode('utf-8')
        h = SHA256.new()
        h.update(buf)
        h = h.hexdigest()

        if SL.rsaVal(h,sig,vPubN, vPubE) == False:
            print("locking public key invalid, abort")
        else:
            print(True)

        if not cleanup(tD, aPubN, aPubE):
            print("error")
            return

        key = findKey(aPriN,aPriD,bits,tD)
        valid = valMacs(tD,key)

        if valid == False:
            print("A tag did not match the file, abort")

        decryptDir(tD, key)
        return


if __name__ == '__main__':
    main()
