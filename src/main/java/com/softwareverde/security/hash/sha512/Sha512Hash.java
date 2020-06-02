package com.softwareverde.security.hash.sha512;

import com.softwareverde.security.hash.Hash;
import com.softwareverde.util.ByteUtil;

import java.util.Comparator;

public interface Sha512Hash extends Hash, Comparable<Sha512Hash> {
    Comparator<Sha512Hash> COMPARATOR = new Comparator<Sha512Hash>() {
        @Override
        public int compare(final Sha512Hash hash0, final Sha512Hash hash1) {
            for (int i = 0; i < BYTE_COUNT; ++i) {
                final int b0 = ByteUtil.byteToInteger(hash0.getByte(i));
                final int b1 = ByteUtil.byteToInteger(hash1.getByte(i));

                if (b0 < b1) { return -1; }
                if (b0 > b1) { return 1; }
            }
            return 0;
        }
    };

    static Sha512Hash fromHexString(final String hexString) {
        return ImmutableSha512Hash.fromHexString(hexString);
    }

    static Sha512Hash copyOf(final byte[] bytes) {
        return ImmutableSha512Hash.copyOf(bytes);
    }

    static Sha512Hash wrap(final byte[] bytes) {
        return MutableSha512Hash.wrap(bytes);
    }

    Integer BYTE_COUNT = 64;
    ImmutableSha512Hash EMPTY_HASH = new ImmutableSha512Hash();

    @Override
    Sha512Hash toReversedEndian();

    @Override
    ImmutableSha512Hash asConst();

    @Override
    default int compareTo(final Sha512Hash sha512Hash) {
        return COMPARATOR.compare(this, sha512Hash);
    }
}
