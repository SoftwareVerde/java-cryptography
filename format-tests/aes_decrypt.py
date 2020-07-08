#!/usr/bin/env python3

import binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = binascii.unhexlify('23B3E2B8FFB06B330750AABF727B55E3D31E19AA1AAA77D0E70988F57FE2FD82')
ciphertext = binascii.unhexlify('010C1A6CB9E30EEDB700FD101B03109266C9A8D67FD85D405C6FA9620D0954F8FF64E1')
plaintext = b'Test'

formatVersion = int(ciphertext[0])
ivLength = int(ciphertext[1])
ivEnd = 2 + ivLength

iv = ciphertext[2:ivEnd]
tagLength = int(ciphertext[ivEnd])
tagEnd = ivEnd + tagLength + 1
authenticationTag = ciphertext[ivEnd+1:tagEnd]
encryptedData = ciphertext[tagEnd:]

aesGcmKey = AESGCM(key)
message = aesGcmKey.decrypt(iv, encryptedData + authenticationTag, None)
print('Pass' if (plaintext == message) else 'Fail')
