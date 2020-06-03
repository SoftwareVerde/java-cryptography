package com.softwareverde.cryptography.hash.ripemd160;

import com.softwareverde.constable.Const;
import com.softwareverde.logging.Logger;
import com.softwareverde.cryptography.hash.ImmutableHash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class ImmutableRipemd160Hash extends ImmutableHash implements Ripemd160Hash, Const {
    public static ImmutableRipemd160Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        if (hashBytes == null) { return null; }

        return new ImmutableRipemd160Hash(hashBytes);
    }

    public static ImmutableRipemd160Hash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }

        return new ImmutableRipemd160Hash(bytes);
    }

    protected ImmutableRipemd160Hash(final byte[] bytes) {
        super(new byte[BYTE_COUNT]);

        if (bytes.length != BYTE_COUNT) {
            throw new RuntimeException("Invalid byte count: " + bytes.length);
        }

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
