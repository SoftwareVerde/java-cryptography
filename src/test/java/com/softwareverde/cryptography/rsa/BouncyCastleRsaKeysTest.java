package com.softwareverde.cryptography.rsa;

import com.softwareverde.cryptography.pgp.PgpKeys;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Assert;
import org.junit.Test;

import java.io.IOException;
import java.util.Random;

public class BouncyCastleRsaKeysTest {
    private static final char[] password = "password".toCharArray();
    private static PgpKeys pgpKeys;

    static {
        try {
            pgpKeys = new PgpKeys("test", password);
        } catch (Exception e) {
            e.printStackTrace(System.err);
        }
    }

    @Test
    public void should_encrypt_and_decrypt_message() throws PGPException, IOException {
        final byte[] message = "this is a test".getBytes();

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaEncryptionKeys(password);
        final byte[] ciphertext = rsaKeys.encrypt(message);
        final byte[] plaintext = rsaKeys.decrypt(ciphertext);

        Assert.assertArrayEquals(message, plaintext);
    }

    @Test
    public void should_not_encrypt_long_message() throws PGPException, IOException {
        final byte[] message = "this is a test".getBytes();

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaEncryptionKeys(password);
        final byte[] ciphertext = rsaKeys.encrypt(message);
        final byte[] plaintext = rsaKeys.decrypt(ciphertext);

        Assert.assertArrayEquals(message, plaintext);
    }

    @Test
    public void should_not_decrypt_modified_ciphertext() throws PGPException, IOException {
        final byte[] message = new byte[4096];
        final Random random = new Random();
        random.nextBytes(message);

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaEncryptionKeys(password);
        final byte[] ciphertext = rsaKeys.encrypt(message);

        Assert.assertNull(ciphertext);
    }

    @Test
    public void should_sign_and_verify_message() throws PGPException, IOException {
        final byte[] message = "this is a test".getBytes();

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaSigningKeys(password);

        final byte[] signature = rsaKeys.sign(message);
        final boolean isValid = rsaKeys.verify(message, signature);

        Assert.assertTrue(isValid);
    }

    @Test
    public void should_sign_and_verify_long_message() throws PGPException, IOException {
        final byte[] message = new byte[4096];
        final Random random = new Random();
        random.nextBytes(message);

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaSigningKeys(password);

        final byte[] signature = rsaKeys.sign(message);
        final boolean isValid = rsaKeys.verify(message, signature);

        Assert.assertTrue(isValid);
    }

    @Test
    public void should_verify_modified_signature() throws PGPException, IOException {
        final byte[] message = "this is a test".getBytes();

        final BouncyCastleRsaKeys rsaKeys = (BouncyCastleRsaKeys) pgpKeys.getRsaSigningKeys(password);

        final byte[] signature = rsaKeys.sign(message);
        signature[0] = (byte) ~signature[0];
        final boolean isValid = rsaKeys.verify(message, signature);

        Assert.assertFalse(isValid);
    }
}
