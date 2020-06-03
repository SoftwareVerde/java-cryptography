package com.softwareverde.cryptography.hash.ripemd160;

import com.softwareverde.cryptography.hash.Hash;

public interface Ripemd160Hash extends Hash {
    Integer BYTE_COUNT = 20;

    static Ripemd160Hash fromHexString(final String hexString) {
        return ImmutableRipemd160Hash.fromHexString(hexString);
    }

    static Ripemd160Hash copyOf(final byte[] bytes) {
        return ImmutableRipemd160Hash.copyOf(bytes);
    }

    static Ripemd160Hash wrap(final byte[] bytes) {
        return MutableRipemd160Hash.wrap(bytes);
    }

    @Override
    public Ripemd160Hash toReversedEndian();

    @Override
    ImmutableRipemd160Hash asConst();
}
