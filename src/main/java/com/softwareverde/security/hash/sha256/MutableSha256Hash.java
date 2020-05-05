package com.softwareverde.security.hash.sha256;

import com.softwareverde.logging.Logger;
import com.softwareverde.security.hash.MutableHash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class MutableSha256Hash extends MutableHash implements Sha256Hash {
    public static MutableSha256Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        return MutableSha256Hash.wrap(hashBytes);
    }

    public static MutableSha256Hash wrap(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }
        return new MutableSha256Hash(bytes);
    }

    public static MutableSha256Hash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }
        return new MutableSha256Hash(ByteUtil.copyBytes(bytes));
    }

    protected MutableSha256Hash(final byte[] bytes) {
        super(bytes);

        if (bytes.length != BYTE_COUNT) {
            throw new RuntimeException("Invalid byte count: " + bytes.length);
        }
    }

    public MutableSha256Hash() {
        super(BYTE_COUNT);
    }

    public MutableSha256Hash(final Sha256Hash hash) {
        super(hash);
    }

    @Override
    public MutableSha256Hash toReversedEndian() {
        return MutableSha256Hash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    public void setBytes(final byte[] bytes) {
        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Attempted to set hash bytes of incorrect length: "+ bytes.length);
            return;
        }

        if (_bytes.length != bytes.length) {
            _bytes = new byte[bytes.length];
        }
        ByteUtil.setBytes(_bytes, bytes);
    }

    public void setBytes(final Sha256Hash hash) {
        ByteUtil.setBytes(_bytes, hash.getBytes());
    }

    @Override
    public ImmutableSha256Hash asConst() {
        return new ImmutableSha256Hash(this);
    }
}
