#!/usr/bin/env python3

import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = binascii.unhexlify('23B3E2B8FFB06B330750AABF727B55E3D31E19AA1AAA77D0E70988F57FE2FD82')
iv = binascii.unhexlify('1A6CB9E30EEDB700FD101B03')
plaintext = b'Test'
expected= binascii.unhexlify('010C1A6CB9E30EEDB700FD101B03109266C9A8D67FD85D405C6FA9620D0954F8FF64E1')

aesGcmKey = AESGCM(key)
ciphertext = aesGcmKey.encrypt(iv, plaintext, None)

encryptedData = ciphertext[:-16]
authenticationTag = ciphertext[-16:]

output = bytes([1]) + bytes([len(iv)]) + iv + bytes([len(authenticationTag)]) + authenticationTag + encryptedData

print('Pass' if (output == expected) else 'Fail')

