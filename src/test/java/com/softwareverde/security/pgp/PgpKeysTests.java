package com.softwareverde.security.pgp;

import com.softwareverde.security.rsa.BouncyCastleRsaKeys;
import com.softwareverde.security.rsa.RsaKeys;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.Arrays;

public class PgpKeysTests {
    private static char[] password = "password".toCharArray();
    private static PgpKeys pgpKeys;

    @BeforeClass
    public static void setup() throws PGPException, IOException {
        final File configurationDirectory = new File(System.getProperty("java.io.tmpdir") + "/test");
        if ( ! configurationDirectory.exists() && ! configurationDirectory.mkdir()) {
            throw new RuntimeException("Unable to create configuration directory.");
        }
        pgpKeys = new PgpKeys("test@example.com", password, configurationDirectory);
    }

    @Test
    public void should_encrypt_and_decrypt_ascii_data() throws PGPException {
        // Setup
        RsaKeys rsaKeys = pgpKeys.getRsaEncryptionKeys(password);

        // Action
        byte[] data = "Test".getBytes();
        byte[] encryptedData = rsaKeys.encrypt(data);
        byte[] decryptedData = rsaKeys.decrypt(encryptedData);

        // Assert
        Assert.assertFalse(Arrays.equals(encryptedData, decryptedData));
        Assert.assertArrayEquals(data, decryptedData);
    }

    @Test
    public void should_encrypt_and_decrypt_binary_data() throws PGPException {
        // Setup
        RsaKeys rsaKeys = pgpKeys.getRsaEncryptionKeys(password);

        // Action
        byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        byte[] encryptedData = pgpKeys.rsaEncrypt(data);
        byte[] decryptedData = pgpKeys.rsaDecrypt(encryptedData, password);

        // Assert
        Assert.assertFalse(Arrays.equals(encryptedData, decryptedData));
        Assert.assertArrayEquals(data, decryptedData);
    }

    @Test
    public void should_decrypt_when_encrypted_with_public_key_only() throws PGPException {
        // Setup
        PGPPublicKey publicKey = pgpKeys.getEncryptionKey();

        // Action
        byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        byte[] encryptedData = BouncyCastleRsaKeys.encryptWithPublicKey(publicKey, data);
        byte[] decryptedData = pgpKeys.rsaDecrypt(encryptedData, password);

        // Assert
        Assert.assertFalse(Arrays.equals(encryptedData, decryptedData));
        Assert.assertArrayEquals(data, decryptedData);
    }

    @Test
    public void should_sign_and_verify_ascii_data() throws PGPException {
        // Setup
        RsaKeys rsaKeys = pgpKeys.getRsaSigningKeys(password);

        // Action
        byte[] data = "Test".getBytes();
        byte[] signature = rsaKeys.sign(data);
        boolean valid = rsaKeys.verify(data, signature);

        // Assert
        Assert.assertTrue(valid);
    }

    @Test
    public void should_sign_and_verify_binary_data() throws PGPException {
        // Setup

        // Action
        byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        byte[] signature = pgpKeys.rsaSign(data, password);
        boolean valid = pgpKeys.rsaVerify(data, signature);

        // Assert
        Assert.assertTrue(valid);
    }

    @Test
    public void should_reject_invalid_signature() throws PGPException {
        // Setup
        RsaKeys rsaKeys = pgpKeys.getRsaSigningKeys(password);

        // Action
        byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        byte[] signature = rsaKeys.sign(data);
        signature[0] ^= 0xFF; // invalidate signature
        boolean valid = rsaKeys.verify(data, signature);

        // Assert
        Assert.assertFalse(valid);
    }

    @Test
    public void should_verify_signature_with_public_key_only() throws PGPException {
        // Setup
        RsaKeys rsaKeys = pgpKeys.getRsaSigningKeys(password);
        PGPPublicKey publicKey = pgpKeys.getSignatureVerificationKey();

        // Action
        byte[] data = new byte[256];
        (new SecureRandom()).nextBytes(data);
        byte[] signature = pgpKeys.rsaSign(data, password);
        boolean valid = BouncyCastleRsaKeys.verifyWithPublicKey(publicKey, data, signature);

        // Assert
        Assert.assertTrue(valid);
    }
}
