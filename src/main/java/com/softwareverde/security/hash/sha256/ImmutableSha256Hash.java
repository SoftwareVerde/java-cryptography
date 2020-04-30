package com.softwareverde.security.hash.sha256;

import com.softwareverde.constable.Const;
import com.softwareverde.logging.Logger;
import com.softwareverde.security.hash.ImmutableHash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class ImmutableSha256Hash extends ImmutableHash implements Sha256Hash, Const {
    public static ImmutableSha256Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        if (hashBytes == null) { return null; }
        if (hashBytes.length != BYTE_COUNT) { return null; }

        return new ImmutableSha256Hash(hashBytes);
    }

    public static ImmutableSha256Hash copyOf(final byte[] bytes) {
        if (bytes.length != BYTE_COUNT) { return null; }
        return new ImmutableSha256Hash(bytes);
    }

    protected ImmutableSha256Hash(final byte[] bytes) {
        super(new byte[BYTE_COUNT]);
        ByteUtil.setBytes(_bytes, bytes);
    }

    public ImmutableSha256Hash() {
        super(new byte[BYTE_COUNT]);
    }

    public ImmutableSha256Hash(final Sha256Hash hash) {
        super(hash);
    }

    @Override
    public MutableSha256Hash toReversedEndian() {
        return MutableSha256Hash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    @Override
    public ImmutableSha256Hash asConst() {
        return this;
    }
}