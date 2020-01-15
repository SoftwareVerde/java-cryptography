package com.softwareverde.security;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.net.URI;
import java.security.SecureRandom;

public class GoogleAuthenticator {
    private static final int DEFAULT_SECRET_KEY_SIZE = 20; // 160-bits, as recommended by RFC 4226 §4
    private static final int DEFAULT_VERIFICATION_WINDOW = 0; // i.e. only current code is valid

    public static String newTwoFactorKey() {
        return newTwoFactorKey(DEFAULT_SECRET_KEY_SIZE);
    }

    public static String newTwoFactorKey(final int keySizeInBytes) {
        final byte[] rawKey = new byte[keySizeInBytes];
        final SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(rawKey);

        return GoogleAuthenticator.encodeSecret(rawKey);
    }

    public static String newKeyUri(final String secret, final String organization, final String accountIdentifier) {
        try {
            final URI uri = new URI(
                "otpauth",
                "totp",
                "/" + organization + ":" + accountIdentifier,
                "secret=" + secret + "&issuer=" + organization,
                null
            );
            return uri.toString();
        }
        catch (final Exception exception) {
            throw new RuntimeException("Problem creating key URI", exception);
        }
    }

    public static String encodeSecret(final byte[] secret) {
        final Base32 base32 = new Base32();
        return base32.encodeAsString(secret).toLowerCase();
    }

    public static byte[] decodeSecret(final String secret) {
        final Base32 base32 = new Base32();
        byte[] decodedKey = base32.decode(secret);
        return decodedKey;
    }

    private final int _verificationWindow;

    public GoogleAuthenticator() {
        _verificationWindow = DEFAULT_VERIFICATION_WINDOW;
    }

    public GoogleAuthenticator(final int verificationWindow) {
        _verificationWindow = verificationWindow;
    }

    /**
     * <p>Checks the provided code using the given secret and the current time.</p>
     *
     * <p>The secret is expected to be the Base32 representation of the secret key.</p>
     * @param secret
     * @param code
     * @return
     */
    public boolean checkCode(final String secret, final long code) {
        return checkCode(secret, code, System.currentTimeMillis());
    }

    /**
     * <p>Checks the provided code using the given secret and timestamp.</p>
     *
     * <p>The secret is expected to be the Base32 representation of the secret key.</p>
     * @param secret
     * @param code
     * @param timestamp
     * @return
     */
    public boolean checkCode(final String secret, final long code, final long timestamp) {
        final byte[] decodedKey = GoogleAuthenticator.decodeSecret(secret);
        return _checkCode(decodedKey, code, timestamp);
    }

    /**
     * <p>Checks the provided code using the given secret and the current time.</p>
     *
     * <p>The secret is expected to be the raw secret key.</p>
     * @param secret
     * @param code
     * @return
     */
    public boolean checkCode(final byte[] secret, final long code) {
        return checkCode(secret, code, System.currentTimeMillis());
    }

    /**
     * <p>Checks the provided code using the given secret and timestamp.</p>
     *
     * <p>The secret is expected to be the raw secret key.</p>
     * @param secret
     * @param code
     * @param timestamp
     * @return
     */
    public boolean checkCode(final byte[] secret, final long code, final long timestamp) {
        return _checkCode(secret, code, timestamp);
    }

    /**
     * <p>Checks the provided code using the given secret and timestamp.</p>
     *
     * <p>The secret should be the raw bytes of the secret key.</p>
     * @param secret
     * @param code
     * @param timestamp
     * @return
     */
    protected boolean _checkCode(byte[] secret, long code, long timestamp) {
        try {
            long reducedTimestamp = _reduceTimestamp(timestamp);
            int window = _verificationWindow;
            for (int i = -window; i <= window; ++i) {
                long hash = _getCodeForReducedTimestamp(secret, reducedTimestamp + i);

                if (hash == code) {
                    return true;
                }
            }

            // The validation code is invalid.
            return false;
        }
        catch (final Exception exception) {
            throw new RuntimeException("Unable to check authentication code", exception);
        }
    }

    protected long _reduceTimestamp(final long timestampInMilliseconds) {
        // get number of 30-second periods since unix epoch
        return timestampInMilliseconds / 1000 / 30;
    }

    protected int _getCodeForReducedTimestamp(byte[] key, long timestamp) {
        try {
            byte[] data = new byte[8];
            long value = timestamp;
            for (int i = 8; i-- > 0; value >>>= 8) {
                data[i] = (byte) value;
            }

            SecretKeySpec signKey = new SecretKeySpec(key, "HmacSHA1");
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(signKey);
            byte[] hash = mac.doFinal(data);

            int offset = hash[20 - 1] & 0xF;

            // We're using a long because Java hasn't got unsigned int.
            long truncatedHash = 0;
            for (int i = 0; i < 4; ++i) {
                truncatedHash <<= 8;
                // We are dealing with signed bytes:
                // we just keep the first byte.
                truncatedHash |= (hash[offset + i] & 0xFF);
            }

            truncatedHash &= 0x7FFFFFFF;
            truncatedHash %= 1000000;

            return (int) truncatedHash;
        }
        catch (final Exception exception) {
            throw new RuntimeException("Unable to check authentication code", exception);
        }
    }
}
