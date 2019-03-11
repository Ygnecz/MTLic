# Mikrotik license file structure
Assume this Mikrotik license:
```
-----BEGIN MIKROTIK SOFTWARE KEY------------
VIhB6/0yhAE1MS8JVjH7Qbw3pTtkCl+yuWVK3lTvh1HZ
uMYTZfzV17711ZBGkYVYR7bdJFrJZtGzc4IyOqPjEA==
-----END MIKROTIK SOFTWARE KEY--------------
```
Removing header and footer we got
`VIhB6/0yhAE1MS8JVjH7Qbw3pTtkCl+yuWVK3lTvh1HZuMYTZfzV17711ZBGkYVYR7bdJFrJZtGzc4IyOqPjEA==`
which seems to be BASE64 encoded. But it isn't. Lets look closer on it. 

First four characters `VIhB` are encoded to first three bytes of license. `VIhB` in BASE64 is `0x15 0x08 0x21 0x01`. In 6-bits format `010101 001000 100001 000001`.  

Lets label these bits.
```
010101 001000 100001 000001
^^^^^^ ^^^^^^ ^^^^^^ ^^^^^^
012345 6789AB CDEFGH IJKLMN
```
Classical BASE64 decodes this bit stream to bytes like this (adds highest bits from next byte to missing lowest bits [link](https://en.wikipedia.org/wiki/Base64#Examples))
```
01010100 10001000 01000001
^^^^^^^^ ^^^^^^^^ ^^^^^^^^
01234567 89ABCDEF GHIJKLMN
```
Which is `54 88 41`

Mikrotik decodes it in a different way (adds lowest bits from next byte to missing highest bits).
```
00010101 00010010 00000110
^^^^^^^^ ^^^^^^^^ ^^^^^^^^
AB012345 EFGH6789 IJKLMNCD
```
Which is `15 12 06`

So the License is decoded to
```
00..15 : 15 12 06 fa 4f cb 21 40 d4 8c c4 27 d5 78 ec d0
16..31 : 06 df e9 d4 92 42 e9 cb ae 55 29 77 39 bd 61 7d
32..47 : 64 2e 83 4d d9 37 57 f5 be d7 75 16 18 24 56 61
48..63 : d1 be 75 49 b1 26 59 6b cc 1c 8e c8 8e fa 8c 04
```

Lets take first 16 bytes
```
15 12 06 fa 4f cb 21 40 d4 8c c4 27 d5 78 ec d0
```
Process some kind of transformation/decrypting (see function MT_Transform). Algo name ??
```
d8 d1 70 a6 4c 00 06 01 00 00 00 00 00 00 00 00
```
## Software ID
Decimal Software ID from converted first 6 bytes is `0x004ca670d1d8`. It can be converted to string serial using character table `TN0BYX18S5HZ4IA67DGF3LPCJQRUK9MW2VE` and doing 8x
```
SNTab[Serial % 0x23]
Serial = Serial / 0x23
```
String serial is `JKLMNBYX` or `JKLM-NBYX`.

## License level
Next byte may be RouterOS major version and next byte `01` is License Level. Next bytes may be features bits.

## License signature
Hashing converted bytes with modified SHA256 with Mikrotik custom round constants and initial hash values
```
c4 bc fe b4 cc 6d 0d aa 40 88 38 1b 68 ba 10 fd
e3 1a 2f 10 f9 29 ca 90 80 17 ad af 77 e1 59 3f
```
Modifying 16 bytes of hash
```
hash[8..23] = hash[8..23] xor License[16..31]
hash[31] = (hash[31] & 0x7F) | 0x40
hash[ 0] =  hash[ 0] & 0xF8
```
Result is
```
hash =
c0 bc fe b4 cc 6d 0d aa 46 57 d1 cf fa f8 f9 36
4d 4f 06 67 c0 94 ab ed 80 17 ad af 77 e1 59 7f
```

Extracting license signature from decoded MTBase64 bytes 32..63
```
signature =
64 2e 83 4d d9 37 57 f5 be d7 75 16 18 24 56 61
d1 be 75 49 b1 26 59 6b cc 1c 8e c8 8e fa 8c 04
```
Computing EC-KCDSA (Elliptic curve Curve25519) ([Link](https://en.wikipedia.org/wiki/Curve25519)) using library [Link ](https://github.com/johndoe31415/joeecc)with Mikrotik public key
```
PubKey =
8E 10 67 E4 30 5F CD C0 CF BF 95 C1 0F 96 E5 DF
E8 C4 9A EF 48 6B D1 A4 E2 E9 6C 27 F0 1E 3E 32
```
Y = signature * PubKey + hash * G
Gx for Curve25519 is `9`.

Result of computation
```
Y =
2c d6 61 75 75 2f 25 b3 90 f7 1b 94 f9 ca 7c 67
83 67 2a af 6d 47 e6 ea 25 43 32 63 4c 66 14 27
```
Computing hash2 of Y with modified SHA256
```
06 df e9 d4 92 42 e9 cb ae 55 29 77 39 bd 61 7d <--
36 6a b7 02 14 07 78 13 64 c9 fb 4f c1 50 bb b4
```
Compare License[16..31] with first 16 bytes of hash2
```
06 df e9 d4 ... == 06 df e9 d4 ...
```
Result:
* License is for Software ID `JPFT-SPRK`
* License level is `1`
* License is valid

