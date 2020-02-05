package com.softwareverde.security.hash;

import com.softwareverde.constable.bytearray.ByteArray;

public interface Hash extends ByteArray {
    static Hash fromHexString(final String hexString) {
        return ImmutableHash.fromHexString(hexString);
    }

    static Hash copyOf(final byte[] bytes) {
        return ImmutableHash.copyOf(bytes);
    }

    static Hash wrap(final byte[] bytes) {
        return MutableHash.wrap(bytes);
    }

    Hash toReversedEndian();

    @Override
    ImmutableHash asConst();
}
