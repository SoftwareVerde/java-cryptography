package com.softwareverde.cryptography.hash.sha512;

import com.softwareverde.cryptography.hash.MutableHash;
import com.softwareverde.logging.Logger;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class MutableSha512Hash extends MutableHash implements Sha512Hash {
    public static MutableSha512Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        return MutableSha512Hash.wrap(hashBytes);
    }

    public static MutableSha512Hash wrap(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Unable to wrap bytes as hash. Invalid byte count: " + bytes.length);
            return null;
        }
        return new MutableSha512Hash(bytes);
    }

    public static MutableSha512Hash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Unable to wrap bytes as hash. Invalid byte count: " + bytes.length);
            return null;
        }
        return new MutableSha512Hash(ByteUtil.copyBytes(bytes));
    }

    protected MutableSha512Hash(final byte[] bytes) {
        super(bytes);

        if (bytes.length != BYTE_COUNT) {
            throw new RuntimeException("Invalid byte count: " + bytes.length);
        }
    }

    public MutableSha512Hash() {
        super(BYTE_COUNT);
    }

    public MutableSha512Hash(final Sha512Hash hash) {
        super(hash);
    }

    @Override
    public MutableSha512Hash toReversedEndian() {
        return MutableSha512Hash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    public void setBytes(final byte[] bytes) {
        if (bytes.length != BYTE_COUNT) {
            Logger.warn("NOTICE: Attempted to set hash bytes of incorrect length: " + bytes.length);
            return;
        }

        if (_bytes.length != bytes.length) {
            _bytes = new byte[bytes.length];
        }
        ByteUtil.setBytes(_bytes, bytes);
    }

    public void setBytes(final Sha512Hash hash) {
        ByteUtil.setBytes(_bytes, hash.getBytes());
    }

    @Override
    public ImmutableSha512Hash asConst() {
        return new ImmutableSha512Hash(this);
    }
}
