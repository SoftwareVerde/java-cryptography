package com.softwareverde.cryptography.aes;

import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.util.HexUtil;
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

    @Test
    public void should_decrypt_version_1_format() {
        // Setup
        final AesKey aesKey = new AesKey(HexUtil.hexStringToByteArray("23B3E2B8FFB06B330750AABF727B55E3D31E19AA1AAA77D0E70988F57FE2FD82"));
        final MutableByteArray data = MutableByteArray.wrap(StringUtil.stringToBytes("Test"));
        final byte[] encryptedData = HexUtil.hexStringToByteArray("010C1A6CB9E30EEDB700FD101B03109266C9A8D67FD85D405C6FA9620D0954F8FF64E1");

        // Action
        final byte[] decryptedData = aesKey.decrypt(encryptedData);

        // Assert
        Assert.assertFalse(Util.areEqual(encryptedData, decryptedData));
        Assert.assertTrue(Util.areEqual(data, decryptedData));
    }
}
