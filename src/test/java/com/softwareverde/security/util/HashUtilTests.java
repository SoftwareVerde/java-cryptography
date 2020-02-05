package com.softwareverde.security.util;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.security.hash.sha256.Sha256Hash;
import org.junit.Assert;
import org.junit.Test;

public class HashUtilTests {
    @Test
    public void should_hash_sha256_in_place() {
        // Setup
        final byte[] preImage = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        final ByteArray expectedBytes = MutableByteArray.wrap(HashUtil.sha256(HashUtil.sha256(preImage)));

        // Action
        final Sha256Hash doubleSha256Hash = HashUtil.doubleSha256(MutableByteArray.wrap(preImage));

        // Assert
        Assert.assertEquals(expectedBytes, doubleSha256Hash);
    }
}
