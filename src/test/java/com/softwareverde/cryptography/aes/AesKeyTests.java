package com.softwareverde.cryptography.aes;

import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.util.StringUtil;
import com.softwareverde.util.Util;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.security.SecureRandom;

public class AesKeyTests {
    @Test
    public void should_encrypt_and_decrypt_ascii_data() throws IOException {
        // Setup
        final AesKey aesKey = new AesKey(256);

        // Action
        final MutableByteArray data = MutableByteArray.wrap(StringUtil.stringToBytes("Test"));
        final byte[] encryptedData = aesKey.encrypt(data.unwrap());
        final byte[] decryptedData = aesKey.decrypt(encryptedData);

        // Assert
        Assert.assertFalse(Util.areEqual(encryptedData, decryptedData));
        Assert.assertTrue(Util.areEqual(data, decryptedData));
    }

    @Test
    public void should_encrypt_and_decrypt_binary_data() throws IOException {
        // Setup
        final AesKey aesKey = new AesKey(256);

        // Action
        final byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        final byte[] encryptedData = aesKey.encrypt(data);
        final byte[] decryptedData = aesKey.decrypt(encryptedData);

        // Assert
        Assert.assertFalse(Util.areEqual(encryptedData, decryptedData));
        Assert.assertTrue(Util.areEqual(data, decryptedData));
    }
}
