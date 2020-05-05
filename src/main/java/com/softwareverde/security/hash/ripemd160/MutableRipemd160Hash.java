package com.softwareverde.security.hash.ripemd160;

import com.softwareverde.logging.Logger;
import com.softwareverde.security.hash.MutableHash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;

public class MutableRipemd160Hash extends MutableHash implements Ripemd160Hash {
    public static MutableRipemd160Hash fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] hashBytes = HexUtil.hexStringToByteArray(hexString);
        if (hashBytes == null) { return null; }

        return new MutableRipemd160Hash(hashBytes);
    }

    public static MutableRipemd160Hash wrap(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }

        return new MutableRipemd160Hash(bytes);
    }

    public static MutableRipemd160Hash copyOf(final byte[] bytes) {
        if (bytes == null) { return null; }

        if (bytes.length != BYTE_COUNT) {
            Logger.warn("Unable to wrap bytes as hash. Invalid byte count: "+ bytes.length);
            return null;
        }

        return new MutableRipemd160Hash(ByteUtil.copyBytes(bytes));
    }

    protected MutableRipemd160Hash(final byte[] bytes) {
        super(bytes);

        if (bytes.length != BYTE_COUNT) {
            throw new RuntimeException("Invalid byte count: " + bytes.length);
        }
    }

    public MutableRipemd160Hash() {
        super(BYTE_COUNT);
    }

    public MutableRipemd160Hash(final Ripemd160Hash hash) {
        super(hash);
    }

    @Override
    public Ripemd160Hash toReversedEndian() {
        return MutableRipemd160Hash.wrap(ByteUtil.reverseEndian(_bytes));
    }

    public void setBytes(final byte[] bytes) {
        if (bytes.length != BYTE_COUNT) {
            Logger.warn("Attempted to set hash bytes of incorrect length: "+ bytes.length);
            return;
        }

        if (_bytes.length != bytes.length) {
            _bytes = new byte[bytes.length];
        }
        ByteUtil.setBytes(_bytes, bytes);
    }

    public void setBytes(final Ripemd160Hash hash) {
        ByteUtil.setBytes(_bytes, hash.getBytes());
    }

    @Override
    public ImmutableRipemd160Hash asConst() {
        return new ImmutableRipemd160Hash(this);
    }
}
