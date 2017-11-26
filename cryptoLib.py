#!/usr/bin/env python3

import binascii
import os
import operator
import sys
import argparse
from Crypto.Cipher import AES
from multiprocessing import Pool

def hexify(message):
    return binascii.hexlify(bytearray(message)).decode('utf-8')

def dehexify(hext):
    text = binascii.unhexlify(hext)
    return text.decode('utf-8')

#XOR two raw byte strings
def xorify(block, iv):
    #result = "%x" % (int(binascii.hexlify(block), 16) ^ int(binascii.hexlify(iv),16))
    #result = format(result,'0>32')
    #result = binascii.unhexlify(result.strip())
    #int_block = int.from_bytes(block, byteorder = 'big', signed = False)
    #int_iv = int.from_bytes(iv, byteorder= 'big', signed = False)
    #x = int_block ^ int_iv
    #return x.to_bytes(len(block), byteorder= 'big', signed = False)
     
    #This finally worked!!!!
    return bytes(map(operator.xor, block, iv))

#Generate an IV in raw bytes
def genIV():
    return os.urandom(16) 

#Takes a message of plain text and breaks it into blocks of 128 bits.
def blockify(message):
    blocks = []
    while message:
        blocks.append(message[:16])
        message = message[16:]
    return blocks

#Takes blocks of 128 bits and turns it into a single string.
def deblockify(blocks):
    message = bytes('', encoding='utf-8')
    for i in blocks:
        message += i
    return message

#Pads the blocks of the message with int converted into chars.
def padify(blocks):
    need = 0
    padding = 0
    for i in blocks:
        if len(i) < 16:
            tot = 16 - len(i)
            need = 1
    if need == 0:
        pad = chr(16) * 16 
        blocks.append(pad)
        return blocks
    elif need == 1:
        pad = tot.to_bytes(1, byteorder= 'big', signed = False)  * tot
        blocks[-1] = blocks[-1] + pad
        return blocks

#Takes off the padding.
def depadify(blocks):
    last = blocks[-1]
    byte = int(last[-2])
    if byte == 16:
        blocks = blocks[:-1]
        return blocks    
    else:
        trim = byte
        blocks[-1] = last[:-trim]
        return blocks


def encrypt(key, raw):
    '''
    Takes in a string of clear text and encrypts it.
        
    @param raw: a string of clear text
    @return: a string of encrypted ciphertext
    '''
    if (raw is None) or (len(raw) == 0):
        raise ValueError('input text cannot be null or empty set')
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    ciphertext = cipher.encrypt(raw)
    return  binascii.hexlify(bytearray(ciphertext)).decode('utf-8')
    
def decrypt(key, enc):
    if (enc is None) or (len(enc) == 0):
        raise ValueError('input text cannot be null or empty set')
    enc = binascii.unhexlify(enc)
    cipher = AES.AESCipher(key[:32], AES.MODE_ECB)
    enc = cipher.decrypt(enc)
    return enc

def cbc_enc(message,iv,key):
    ciblocks = []
    ciblocks.append(hexify(iv))
    newiv = iv
    blocks = blockify(message)
    blocks = padify(blocks)
    for i in blocks:
        ciblock = xorify(i,newiv)
        ciphertext = encrypt(key,ciblock)
        ciblocks.append(ciphertext)
        ciphertext = binascii.unhexlify(ciphertext)
        newiv = ciphertext
    return ciblocks

def cbc_dec(ciblocks,key):
    dec = []
    ciblocks.reverse()
    num = len(ciblocks)
    for i in range(num - 1):
        hext = ciblocks[0]
        iv = binascii.unhexlify(ciblocks[1])
        decblock = decrypt(key, hext)
        decblock = xorify(decblock,iv)
        dec.insert(0, decblock)
        del ciblocks[0] 
    dec = depadify(dec)
    message = deblockify(dec)
    return message

def multi_process(key, ctrs, blocks):
    for index in range(1,len(ctrs)):
        ctr = binascii.unhexlify(encrypt(key, ctrs[index]))
        block = blocks[index]
        result = xorify(block, ctr)
        ctrs[index] = hexify(result)
    return ctrs

def ctr_enc(message, iv, key): 
    blocks = blockify(message)
    blocks.insert(0,'0')   #added this to make blocks and ciblocks the same length
    ciblocks = []
    
    ciblocks.append(hexify(iv))
  
    for i in range(1,len(blocks)):
        #iv = binascii.unhexlify(format("%x" % (int(binascii.hexlify(iv), 16) + 1),'0>32'))
        ivint = int.from_bytes(iv, byteorder = 'big', signed = False) + 1
        iv = ivint.to_bytes(len(iv), byteorder = 'big', signed = False)
        ciblocks.append(iv)
  
    p = Pool()
    ciblocks = p.apply(multi_process,args=(key,ciblocks,blocks,))
    
    p.close()
    return ciblocks
 
def ctr_dec(ciblocks, key):
    iv = binascii.unhexlify(ciblocks[0])
    blocks = []
 
    blocks.append(iv)
 
    for i in range(1,len(ciblocks)):
        #iv = binascii.unhexlify(format("%x" % (int(binascii.hexlify(iv), 16) + 1),'0>32'))
        ivint = int.from_bytes(iv, byteorder = 'big', signed = False) + 1
        iv = ivint.to_bytes(len(iv), byteorder = 'big', signed = False)
        blocks.append(iv)
        ciblocks[i] = binascii.unhexlify(ciblocks[i])
    
    
    p = Pool()
    blocks = p.apply(multi_process,args=(key,blocks,ciblocks,))
    p.close() 
    del blocks[0]
    
    for i in range(len(blocks)):
        blocks[i] = binascii.unhexlify(blocks[i])
 
    message = deblockify(blocks)
    return message    

def main():
    blocks = []
 
    parser = argparse.ArgumentParser()
    parser.add_argument('mode')
    parser.add_argument('-k')
    parser.add_argument('-i')
    parser.add_argument('-o')
    parser.add_argument('-v', nargs ='?')
    
    args = parser.parse_args()
    
    mode = args.mode
  
    kfile = open(args.k)
    key = kfile.readline()
    key = key.rstrip('\n')
    key = binascii.unhexlify(key)


    if args.v != None:
        ivfile = open(args.v)
        iv = ivfile.readline()
        iv = iv.rstrip('\n')
        iv = binascii.unhexlify(iv)
    else:
        iv = genIV()

    
    if mode == "cbc-enc":
        ifile = open(args.i, 'rb')
        output = open(args.o, 'w')
        message = bytes('', encoding='utf-8')
        for line in ifile:
            message += line
        blocks = cbc_enc(message,iv,key)
        
        for i in blocks:
            output.write("%s\n" % i)

    elif mode == "cbc-dec":
        ifile = open(args.i, 'r')
        output = open(args.o, 'wb')
        blocks = ifile.readlines()
        for i in range(len(blocks)):
            blocks[i] = blocks[i].strip('\n')
        message = cbc_dec(blocks, key)
        output.write(message)

    elif mode == "ctr-enc":
        ifile = open(args.i, 'rb')
        output = open(args.o, 'w') 
        message = bytes('', encoding='utf-8')
        for line in ifile:
            message += line
        blocks = ctr_enc(message,iv,key)
     
        for i in blocks:
            output.write("%s\n" % i)

    elif mode == "ctr-dec":
        ifile = open(args.i, 'r')
        output = open(args.o, 'wb')
        blocks = ifile.readlines()
        for i in range(len(blocks)):
            blocks[i] = blocks[i].strip('\n')
        message = ctr_dec(blocks,key)
        output.write(message)

    else:
        print("Not a valid mode")
        return

if __name__ == "__main__":
     main()

