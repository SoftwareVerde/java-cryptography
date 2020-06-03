package com.softwareverde.cryptography.hash.sha512;

import com.softwareverde.constable.Const;
import com.softwareverde.logging.Logger;
import com.softwareverde.cryptography.hash.ImmutableHash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class ImmutableSha512Hash extends ImmutableHash implements Sha512Hash, Const {
    public static ImmutableSha512Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        if (hashBytes == null) { return null; }
        if (hashBytes.length != BYTE_COUNT) { return null; }

        return new ImmutableSha512Hash(hashBytes);
    }

    public static ImmutableSha512Hash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }
        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }
        return new ImmutableSha512Hash(bytes);
    }

    protected ImmutableSha512Hash(final byte[] bytes) {
        super(new byte[BYTE_COUNT]);

        if (bytes.length != BYTE_COUNT) {
            throw new RuntimeException("Invalid byte count: " + bytes.length);
        }

        ByteUtil.setBytes(_bytes, bytes);
    }

    public ImmutableSha512Hash() {
        super(new byte[BYTE_COUNT]);
    }

    public ImmutableSha512Hash(final Sha512Hash hash) {
        super(hash);
    }

    @Override
    public MutableSha512Hash toReversedEndian() {
        return MutableSha512Hash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    @Override
    public ImmutableSha512Hash asConst() {
        return this;
    }
}
