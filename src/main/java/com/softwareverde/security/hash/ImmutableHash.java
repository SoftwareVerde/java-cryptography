package com.softwareverde.security.hash;

import com.softwareverde.constable.Const;
import com.softwareverde.constable.bytearray.overflow.ImmutableOverflowingByteArray;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class ImmutableHash extends ImmutableOverflowingByteArray implements Hash, Const {
    public static ImmutableHash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        if (hashBytes == null) { return null; }

        return new ImmutableHash(hashBytes);
    }

    public static ImmutableHash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }
        return new ImmutableHash(bytes);
    }

    protected ImmutableHash(final byte[] bytes) {
        super(bytes);
    }

    public ImmutableHash() {
        super(new byte[0]);
    }

    public ImmutableHash(final Hash hash) {
        super(hash);
    }

    @Override
    public Hash toReversedEndian() {
        return MutableHash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    @Override
    public ImmutableHash asConst() {
        return this;
    }
}
