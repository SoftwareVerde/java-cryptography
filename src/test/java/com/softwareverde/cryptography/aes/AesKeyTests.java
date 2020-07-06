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
    public void should_perform_legacy_decryption_with_implied_authentication_tag_length() {
        // Setup
        final AesKey aesKey = new AesKey(HexUtil.hexStringToByteArray("943CBFA720FA5B76BC8C31CDB618E166221AE8644D3B00F567C77EA4DBD7D9AA"));
        final MutableByteArray data = MutableByteArray.wrap(StringUtil.stringToBytes("Test"));
        final byte[] cipherText = HexUtil.hexStringToByteArray("0C9550E3017B60CEFB003B4E54A026DFC7533DC92F229CB78D63B42021");

        // Action
        final byte[] decryptedData = aesKey.decrypt(cipherText);

        // Assert
        Assert.assertTrue(Util.areEqual(data, decryptedData));
    }

    @Test
    public void should_perform_decryption_with_specified_authentication_tag_length() {
        // Setup
        final AesKey aesKey = new AesKey(HexUtil.hexStringToByteArray("8AB983E6F8E71519D2B683E564047A7D8CD27E2DC8D6C3DED0C41CA1B1BB8287"));
        final MutableByteArray data = MutableByteArray.wrap(StringUtil.stringToBytes("Test"));
        final byte[] cipherText = HexUtil.hexStringToByteArray("8C10E19046F0A887F4893C04E28398CDD7F00522E8BB9D96B2B0B1D7ED080E7E8D7A");

        // Action
        final byte[] decryptedData = aesKey.decrypt(cipherText);

        // Assert
        Assert.assertTrue(Util.areEqual(data, decryptedData));
    }
}
