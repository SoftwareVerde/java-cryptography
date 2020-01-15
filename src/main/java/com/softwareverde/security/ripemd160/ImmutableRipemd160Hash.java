package com.softwareverde.security.ripemd160;

import com.softwareverde.constable.Const;
import com.softwareverde.security.ImmutableHash;
import com.softwareverde.util.ByteUtil;

public class ImmutableRipemd160Hash extends ImmutableHash implements Ripemd160Hash, Const {
    public static ImmutableRipemd160Hash copyOf(final byte[] bytes) {
        return new ImmutableRipemd160Hash(bytes);
    }

    protected ImmutableRipemd160Hash(final byte[] bytes) {
        super(new byte[BYTE_COUNT]);
        ByteUtil.setBytes(_bytes, bytes);
    }

    public ImmutableRipemd160Hash() {
        super(new byte[BYTE_COUNT]);
    }

    public ImmutableRipemd160Hash(final Ripemd160Hash hash) {
        super(new byte[BYTE_COUNT]);
        ByteUtil.setBytes(_bytes, hash.getBytes());
    }

    @Override
    public Ripemd160Hash toReversedEndian() {
        return new MutableRipemd160Hash(ByteUtil.reverseEndian(_bytes));
    }

    @Override
    public ImmutableRipemd160Hash asConst() {
        return this;
    }
}
