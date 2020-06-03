package com.softwareverde.cryptography.hash.sha256;

import com.softwareverde.cryptography.hash.Hash;
import com.softwareverde.util.ByteUtil;

import java.util.Comparator;

public interface Sha256Hash extends Hash, Comparable<Sha256Hash> {
    Comparator<Sha256Hash> COMPARATOR = new Comparator<Sha256Hash>() {
        @Override
        public int compare(final Sha256Hash hash0, final Sha256Hash hash1) {
            for (int i = 0; i < BYTE_COUNT; ++i) {
                final int b0 = ByteUtil.byteToInteger(hash0.getByte(i));
                final int b1 = ByteUtil.byteToInteger(hash1.getByte(i));

                if (b0 < b1) { return -1; }
                if (b0 > b1) { return 1; }
            }
            return 0;
        }
    };

    static Sha256Hash fromHexString(final String hexString) {
        return ImmutableSha256Hash.fromHexString(hexString);
    }

    static Sha256Hash copyOf(final byte[] bytes) {
        return ImmutableSha256Hash.copyOf(bytes);
    }

    static Sha256Hash wrap(final byte[] bytes) {
        return MutableSha256Hash.wrap(bytes);
    }

    Integer BYTE_COUNT = 32;
    ImmutableSha256Hash EMPTY_HASH = new ImmutableSha256Hash();

    @Override
    Sha256Hash toReversedEndian();

    @Override
    ImmutableSha256Hash asConst();

    @Override
    default int compareTo(final Sha256Hash sha256Hash) {
        return COMPARATOR.compare(this, sha256Hash);
    }
}
