package com.softwareverde.security.aes;

import com.softwareverde.logging.Logger;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.bytearray.ByteArrayBuilder;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;

public class AesKey {
    public static final int DEFAULT_KEY_SIZE = 256;

    private static final String KEY_ALGORITHM = "AES";
    private static final String ENCRYPTION_CIPHER = "AES/GCM/NoPadding"; // Using GCM instead of CBC as it provides authentication
    private static final int INITIALIZATION_VECTOR_LENGTH = 12; // IV size of 12-bytes is specifically recommended for AES-GCM (more efficient than other lengths)

    private SecretKey _key;

    public AesKey() {
        this(DEFAULT_KEY_SIZE);
    }

    public AesKey(int keySize) {
        _key = _createKey(keySize);
    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }

    /**
     * <p>Uses the provided data as an AES encryption key. Must be a valid key length.</p>
     * @param key
     */
    public AesKey(byte[] key) {
        _key = new SecretKeySpec(key, 0, key.length, KEY_ALGORITHM);
    }

    private SecretKey _createKey(int keySize) {
        try {
            final KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
            keyGenerator.init(keySize);
            return keyGenerator.generateKey();
        }
        catch (final NoSuchAlgorithmException e) {
            Logger.error("Bad algorithm", e);
            return null;
        }
    }

    private byte[] _createInitializationVector() {
        final byte[] initializationVector = new byte[INITIALIZATION_VECTOR_LENGTH];

        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(initializationVector);

        return initializationVector;
    }

    public SecretKey getKey() {
        return _key;
    }

    public byte[] getBytes() {
        return _key.getEncoded();
    }

    public byte[] encrypt(byte[] plainText) {
        try {
            final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_CIPHER);
            final byte[] initializationVectorBytes = _createInitializationVector();
            final AlgorithmParameterSpec initializationVector = new GCMParameterSpec(initializationVectorBytes.length * Byte.SIZE, initializationVectorBytes);
            aesCipher.init(Cipher.ENCRYPT_MODE, _key, initializationVector);
            final byte[] cipherText = aesCipher.doFinal(plainText);

            // prefix cipher text with initialization vector
            final ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder();
            byteArrayBuilder.appendByte((byte) initializationVectorBytes.length);
            byteArrayBuilder.appendBytes(initializationVectorBytes);
            byteArrayBuilder.appendBytes(cipherText);

            Arrays.fill(initializationVectorBytes, (byte) 0);

            return byteArrayBuilder.build();
        }
        catch (final Exception e) {
            Logger.error("Unable to encrypt data", e);
            return null;
        }
    }

    public byte[] decrypt(byte[] cipherText) {
        try {
            // remove initialization vector from cipher text
            final byte initializationVectorLength = cipherText[0];
            final int cipherTextOffset = ByteUtil.byteToInteger(initializationVectorLength) + 1;
            final byte[] initializationVectorBytes = Arrays.copyOfRange(cipherText, 1, cipherTextOffset);
            final AlgorithmParameterSpec initializationVector = new GCMParameterSpec(initializationVectorLength * Byte.SIZE, initializationVectorBytes);
            final byte[] encryptedData = Arrays.copyOfRange(cipherText, cipherTextOffset, cipherText.length);

            final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_CIPHER);
            aesCipher.init(Cipher.DECRYPT_MODE, _key, initializationVector);
            final byte[] plainText = aesCipher.doFinal(encryptedData);

            Arrays.fill(initializationVectorBytes, (byte) 0);

            return plainText;
        }
        catch (final Exception e) {
            Logger.error("Unable to decrypt data", e);
            return null;
        }
    }
}
