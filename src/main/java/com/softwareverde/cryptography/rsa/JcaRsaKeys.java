package com.softwareverde.cryptography.rsa;


import com.softwareverde.logging.Logger;
import com.softwareverde.logging.LoggerInstance;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import java.security.*;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * <p>Provides a JCA-compatible RSA interface.</p>
 *
 * <p>In order to support modern security standards, the default algorithms require the use of the Bouncy Castle security provider.</p>
 */
public class JcaRsaKeys implements RsaKeys {
    private static final String DEFAULT_CIPHER = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String DEFAULT_SIGNATURE_ALGORITHM = "SHA256withRSA/PSS";

    private static final int DEFAULT_KEY_SIZE = 4096;
    private static final LoggerInstance _logger = Logger.getInstance(JcaRsaKeys.class);

    private final KeyPair _keyPair;
    private String _cipherName;


    public static JcaRsaKeys newKeyPair() {
        try {
            return newKeyPair(DEFAULT_CIPHER, DEFAULT_KEY_SIZE);
        }
        catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("INVALID DEFAULT CIPHER: " + DEFAULT_CIPHER, e);
        }
    }

    public static JcaRsaKeys newKeyPair(final String cipherName, int keyLength) throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(keyLength);
        final KeyPair keyPair = kpg.generateKeyPair();
        return new JcaRsaKeys(keyPair, cipherName);
    }

    public JcaRsaKeys(final KeyPair keyPair, final String cipherName) {
        _keyPair = keyPair;
        _cipherName = cipherName;
    }

    public PublicKey getJcaPublicKey() {
        return _keyPair.getPublic();
    }

    @Override
    public byte[] getPublicKey() {
        return _keyPair.getPublic().getEncoded();
    }

    @Override
    public byte[] encrypt(final byte[] plainText) {
        return encryptWithPublicKey(_cipherName, _keyPair.getPublic(), plainText);
    }

    public static byte[] encryptWithPublicKey(final String cipherName, final PublicKey publicKey, final byte[] plainText) {
        try {
            final Cipher cipher = _createCipher(cipherName, Cipher.ENCRYPT_MODE, publicKey);
            final byte[] cipherText = cipher.doFinal(plainText);
            return cipherText;
        }
        catch (final Exception exception) {
            _logger.error("Unable to perform encryption", exception);
            return null;
        }
    }

    @Override
    public byte[] decrypt(final byte[] cipherText) {
        return decryptWithPrivateKey(_cipherName, _keyPair.getPrivate(), cipherText);
    }

    public static byte[] decryptWithPrivateKey(final String cipherName, final PrivateKey privateKey, final byte[] cipherText) {
        try {
            final Cipher cipher = _createCipher(cipherName, Cipher.DECRYPT_MODE, privateKey);
            final byte[] plainText = cipher.doFinal(cipherText);
            return plainText;
        }
        catch (final Exception exception) {
            _logger.error("Unable to perform decryption", exception);
            return null;
        }
    }

    @Override
    public byte[] sign(final byte[] data) {
        return signWithPrivateKey(_keyPair.getPrivate(), data);
    }

    public static byte[] signWithPrivateKey(final PrivateKey privateKey, final byte[] data) {
        return signWithPrivateKey(privateKey, data, DEFAULT_SIGNATURE_ALGORITHM);
    }

    public static byte[] signWithPrivateKey(final PrivateKey privateKey, final byte[] data, final String signatureAlgorithm) {
        try {
            Signature signature = _getSignatureInstance(signatureAlgorithm);
            signature.initSign(privateKey);
            signature.update(data);
            return signature.sign();
        }
        catch (final Exception exception) {
            _logger.error("Unable to sign data", exception);
            return null;
        }
    }

    @Override
    public boolean verify(final byte[] data, final byte[] signature) {
        return verifySignatureWithPublicKey(_keyPair.getPublic(), data, signature);
    }

    public static boolean verifySignatureWithPublicKey(final PublicKey publicKey, final byte[] data, final byte[] signature) {
        return verifySignatureWithPublicKey(publicKey, data, signature, DEFAULT_SIGNATURE_ALGORITHM);
    }

    public static boolean verifySignatureWithPublicKey(final PublicKey publicKey, final byte[] data, final byte[] signature, final String signatureAlgorithm) {
        try {
            final Signature rsaVerify = _getSignatureInstance(signatureAlgorithm);
            rsaVerify.initVerify(publicKey);
            rsaVerify.update(data);
            return rsaVerify.verify(signature);
        }
        catch (final Exception exception) {
            _logger.error("Unable to verify signature", exception);
            return false;
        }
    }

    protected static Cipher _createCipher(final String cipherName, final int mode, final Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(cipherName);
        // TODO: this could be made more robust/configurable, but isn't generally necessary unless you are trying to match compatibility to an existing system
        if (cipherName.contains("OAEP")) {
            // interprets as OAEPwithSHA-256andMGF1Padding but using MGF1 using SHA-1 (usually unspecified and/or implementation-specific)
            OAEPParameterSpec spec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
            cipher.init(mode, key, spec);
        }
        else {
            cipher.init(mode, key);
        }
        return cipher;
    }

    private static Signature _getSignatureInstance(final String signatureAlgorithm) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException {
        Signature signature = Signature.getInstance(signatureAlgorithm);
        if (signatureAlgorithm.contains("PSS")) {
            // interprets as PSS with SHA-256 and MGF1 with SHA-256
            signature.setParameter(new PSSParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1));
        }
        return signature;
    }
}
