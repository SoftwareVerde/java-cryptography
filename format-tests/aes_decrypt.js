#!/usr/bin/env node

// adapted from https://gist.github.com/rjz/15baffeab434b8125ca4d783f4116d81

const buffer = require('buffer');
const crypto = require('crypto');

var keyHex = '23B3E2B8FFB06B330750AABF727B55E3D31E19AA1AAA77D0E70988F57FE2FD82'
var ciphertextHex = '010C1A6CB9E30EEDB700FD101B03109266C9A8D67FD85D405C6FA9620D0954F8FF64E1'
var plaintext = 'Test'

const ALGO = 'aes-256-gcm';
const decrypt = (key, enc, iv, authTag) => {
    const decipher = crypto.createDecipheriv(ALGO, key, iv);
    decipher.setAuthTag(authTag);
    let str = decipher.update(enc, 'base64', 'utf8');
    str += decipher.final('utf8');
    return str;
};

const key = Buffer.from(keyHex, 'hex');
const ciphertext = Buffer.from(ciphertextHex, 'hex')

const formatVersion = ciphertext.readInt8(0);
const ivLength = ciphertext.readInt8(1);
const ivEnd = 2+ivLength;

const iv = ciphertext.slice(2, ivEnd);
const tagLength = ciphertext.readInt8(ivEnd);
const tagEnd = ivEnd + tagLength + 1;
const authenticationTag = ciphertext.slice(ivEnd+1, tagEnd);
const encryptedData = ciphertext.slice(tagEnd);

var decrypted;
try {
    decrypted = decrypt(key, encryptedData, iv, authenticationTag);
}
catch (error) {
    console.error(error);
}
console.log((decrypted == plaintext) ? "Pass" : "Fail");


