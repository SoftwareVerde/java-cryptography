package com.softwareverde.cryptography.rsa;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Random;

public class JcaRsaKeysTests {
    private static JcaRsaKeys rsaKeys;

    @BeforeClass
    public static void before() {
        Security.addProvider(new BouncyCastleProvider());
        rsaKeys = JcaRsaKeys.newKeyPair();
    }

    @Test
    public void should_create_signature_and_verify_it() {
        final byte[] message = "this is a test".getBytes();

        final byte[] signature = rsaKeys.sign(message);
        final boolean isValid = JcaRsaKeys.verifySignatureWithPublicKey(rsaKeys.getJcaPublicKey(), message, signature);

        Assert.assertTrue(isValid);
    }

    @Test
    public void should_not_verify_modified_signature() {
        final byte[] message = "this is a test".getBytes();

        final byte[] signature = rsaKeys.sign(message);
        signature[0] = (byte) ~signature[0];
        final boolean isValid = JcaRsaKeys.verifySignatureWithPublicKey(rsaKeys.getJcaPublicKey(), message, signature);

        Assert.assertFalse(isValid);
    }

    @Test
    public void should_sign_and_verify_large_message() {
        final byte[] message = new byte[4096];
        final Random random = new Random();
        random.nextBytes(message);

        final byte[] signature = rsaKeys.sign(message);
        final boolean isValid = JcaRsaKeys.verifySignatureWithPublicKey(rsaKeys.getJcaPublicKey(), message, signature);

        Assert.assertTrue(isValid);
    }

    @Test
    public void should_encrypt_and_decrypt() {
        final byte[] message = "this is a test".getBytes();

        final byte[] ciphertext = rsaKeys.encrypt(message);
        final byte[] plaintext = rsaKeys.decrypt(ciphertext);

        Assert.assertArrayEquals(message, plaintext);
    }

    @Test
    public void should_not_encrypt_long_message() {
        final byte[] message = new byte[4096];
        final Random random = new Random();
        random.nextBytes(message);

        final byte[] ciphertext = rsaKeys.encrypt(message);

        Assert.assertNull(ciphertext);
    }

    @Test
    public void should_not_decrypt_modified_ciphertext() {
        final byte[] message = "this is a test".getBytes();

        final byte[] ciphertext = rsaKeys.encrypt(message);
        // using index 4 to ensure length is not what is modified
        ciphertext[4] = (byte) ~ciphertext[4];

        final byte[] plaintext = rsaKeys.decrypt(ciphertext);

        Assert.assertNull(plaintext);
    }
}
