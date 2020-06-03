package com.softwareverde.cryptography.rsa;

public interface RsaKeys {
    byte[] getPublicKey();
    byte[] encrypt(final byte[] plainText);
    byte[] decrypt(final byte[] cipherText);
    byte[] sign(final byte[] data);
    boolean verify(final byte[] data, final byte[] signature);
}
