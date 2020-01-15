package com.softwareverde.security.sha256;

import com.softwareverde.constable.Const;
import com.softwareverde.security.ImmutableHash;
import com.softwareverde.util.ByteUtil;

public class ImmutableSha256Hash extends ImmutableHash implements Sha256Hash, Const {
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
