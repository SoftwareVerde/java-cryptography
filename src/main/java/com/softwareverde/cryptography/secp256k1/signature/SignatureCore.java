package com.softwareverde.cryptography.secp256k1.signature;

import com.softwareverde.constable.bytearray.ByteArray;

public abstract class SignatureCore implements Signature {
    @Override
    public String toString() {
        final ByteArray encoded = this.encode();
        return (encoded != null ? encoded.toString() : null);
    }
}