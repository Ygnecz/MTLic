#!/usr/bin/python3

import sys
import struct
import binascii
import array

from ecc import AffineCurvePoint, getcurvebyname, FieldElement

from MTTools import *

if len(sys.argv) != 2:
    print(sys.argv[0]+" <license file>")
    exit()

with open(sys.argv[1], "r") as licFile:
    lic=licFile.read().split('\n')

if lic[0] != '-----BEGIN MIKROTIK SOFTWARE KEY------------' or \
   lic[3] != '-----END MIKROTIK SOFTWARE KEY--------------':
    print('Not a Mikrotik license file')
    exit()

lic = lic[1]+lic[2]
# MTBase64 decode license
lic = MTBse64Decode(lic)

print("-- MTBase64 decoded")
printBytes(lic)
print()

# MT_Transform license value
licVal = MT_Transform(lic[:16])

print("-- Transformed license")
printBytes(licVal)
print()

# Software ID
SWID = int.from_bytes(licVal[:6], 'little')
print("-- Software ID")
print(hex(SWID))
print(MT_SWSNToSWID(SWID))
print()

# License level
print("-- License level")
print(licVal[7])
print()

# Signature verification
hash = MT_Hash(licVal)

print("-- License hash")
printBytes(hash)
print()

for i in range(16):
  hash[8+i] = hash[8+i] ^ lic[16+i]

hash[31] = (hash[31] & 0x7F) | 0x40;
hash[ 0] =  hash[ 0] & 0xF8;

print("-- Modified license hash")
printBytes(hash)
print()

sig = lic[32:64]
print("-- License signature (from License)")
printBytes(sig)
print()

curve = getcurvebyname("curve25519")

pub="8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32"

pub=binascii.b2a_hex(binascii.a2b_hex(pub)[::-1])
pub=int(pub, 16)

hash = int.from_bytes(hash, 'little')
sig  = int.from_bytes(sig,  'little')

# Py of public key to Px
pub=AffineCurvePoint(pub, int(FieldElement(pub**3+int(curve.a)*pub**2+pub, curve.p).sqrt()[0]), curve)

Y=int((pub*sig + curve.G*hash).x)
Y=Y.to_bytes(32, byteorder='little')

print("-- Elliptic curve computation result")
print("   Y = signature * PubKey + hash * G")
printBytes(Y)
print()

Yhash = MT_Hash(Y)

print("-- MT_Hash of elliptic curve result")
printBytes(Yhash)
print()

print("-- Compare computation result with License")
printBytes(Yhash[:16])
printBytes(lic[16:32])
print("-- Compare result")
if Yhash[:16] == lic[16:32]:
    print('OK - License valid')
else:
    print('Failed')
