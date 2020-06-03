package com.softwareverde.cryptography.secp256k1;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.logging.Logger;
import com.softwareverde.cryptography.hash.sha512.Sha512Hash;
import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.util.Util;
import com.softwareverde.util.bytearray.ByteArrayBuilder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class Ecies {
    protected static ByteArray substring(final ByteArray byteArray, final Integer offset) {
        final int byteCount = (byteArray.getByteCount() - offset);
        return ByteArray.wrap(byteArray.getBytes(offset, byteCount));
    }

    public static class Aes {
        public static final String KEY_ALGORITHM = "AES";
        public static final String ENCRYPTION_CIPHER = "AES/CBC/PKCS7Padding";
        public static final Integer INITIALIZATION_VECTOR_BYTE_COUNT = 16;

        public static ByteArray encrypt(final ByteArray data, final PrivateKey key, final ByteArray initializationVectorBytes) {
            try {
                final SecretKey secretKey = new SecretKeySpec(key.getBytes(), 0, key.getByteCount(), KEY_ALGORITHM);

                final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_CIPHER);
                final AlgorithmParameterSpec initializationVector = new IvParameterSpec(initializationVectorBytes.getBytes());
                aesCipher.init(Cipher.ENCRYPT_MODE, secretKey, initializationVector);
                final byte[] cipherText = aesCipher.doFinal(data.getBytes());

                final ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder();
                byteArrayBuilder.appendBytes(initializationVectorBytes);
                byteArrayBuilder.appendBytes(cipherText);
                return byteArrayBuilder;
            }
            catch (final Exception exception) {
                Logger.error("Unable to encrypt data.", exception);
                return null;
            }
        }

        public static ByteArray decrypt(final ByteArray data, final ByteArray key) {
            try {
                final SecretKey secretKey = new SecretKeySpec(key.getBytes(), 0, key.getByteCount(), KEY_ALGORITHM);

                final byte[] initializationVectorBytes = data.getBytes(0, INITIALIZATION_VECTOR_BYTE_COUNT);
                final AlgorithmParameterSpec initializationVector = new IvParameterSpec(initializationVectorBytes);
                final ByteArray encryptedData = Ecies.substring(data, INITIALIZATION_VECTOR_BYTE_COUNT);

                final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_CIPHER);
                aesCipher.init(Cipher.DECRYPT_MODE, secretKey, initializationVector);
                return ByteArray.wrap(aesCipher.doFinal(encryptedData.getBytes()));
            }
            catch (final Exception exception) {
                Logger.error("Unable to decrypt data.", exception);
                return null;
            }
        }
    }
    protected final PrivateKey _localPrivateKey;
    protected final PublicKey _remotePublicKey;
    protected Boolean _includePublicKey = false;

    protected Sha512Hash _getK() {
        final ECCurve curve = Secp256k1.CURVE_DOMAIN.getCurve();
        final PublicKey decompressedPublicKey = _remotePublicKey.decompress();
        final ECPoint KB = curve.decodePoint(decompressedPublicKey.getBytes());
        final ECPoint P = KB.multiply(new BigInteger(1, _localPrivateKey.getBytes()));
        final BigInteger S = P.normalize().getXCoord().toBigInteger();
        final MutableByteArray sBytes = new MutableByteArray(32);
        sBytes.setBytes(0, S.toByteArray());

        return HashUtil.sha512(sBytes);
    }

    protected PrivateKey _getFirstK() {
        final Sha512Hash k = _getK();
        return PrivateKey.fromBytes(k.getBytes(0, PrivateKey.KEY_BYTE_COUNT));
    }

    protected PrivateKey _getLastK() {
        final Sha512Hash k = _getK();
        return PrivateKey.fromBytes(Ecies.substring(k, PrivateKey.KEY_BYTE_COUNT));
    }

    public Ecies(final PrivateKey privateKey, final PublicKey recipientPublicKey) {
        _localPrivateKey = privateKey;
        _remotePublicKey = recipientPublicKey;
    }

    public void setIncludePublicKey(final Boolean includePublicKey) {
        _includePublicKey = includePublicKey;
    }

    public Boolean getIncludePublicKey() {
        return _includePublicKey;
    }

    public ByteArray encrypt(final ByteArray message) {
        return this.encrypt(message, null);
    }

    public ByteArray encrypt(final ByteArray message, final ByteArray nullableInitializationVector) {
        final PublicKey sendersPublicKey;
        {
            final PublicKey uncompressedPublicKey = _localPrivateKey.getPublicKey();
            sendersPublicKey = uncompressedPublicKey.compress();
        }

        final ByteArray initializationVector;
        {
            final ByteArray hmac = (nullableInitializationVector != null ? nullableInitializationVector : HashUtil.sha256Hmac(message, _localPrivateKey));
            initializationVector = ByteArray.wrap(hmac.getBytes(0, Aes.INITIALIZATION_VECTOR_BYTE_COUNT));
        }

        final ByteArray c;
        {
            final PrivateKey kE = _getFirstK();
            c = Aes.encrypt(message, kE, initializationVector);
            if (c == null) { return null; }
        }

        final ByteArray d;
        {
            final ByteArray ct = Ecies.substring(c, Aes.INITIALIZATION_VECTOR_BYTE_COUNT);
            final ByteArrayBuilder hmacPreImage = new ByteArrayBuilder();
            {
                hmacPreImage.appendBytes(initializationVector);
                if (_includePublicKey) {
                    hmacPreImage.appendBytes(sendersPublicKey);
                }
                hmacPreImage.appendBytes(ct);
            }

            final PrivateKey kM = _getLastK();
            d = HashUtil.sha256Hmac(hmacPreImage, kM);
        }

        final ByteArrayBuilder result = new ByteArrayBuilder();
        {
            if (_includePublicKey) {
                result.appendBytes(sendersPublicKey);
            }
            result.appendBytes(c);
            result.appendBytes(d);
        }

        return result;
    }

    public ByteArray decrypt(final ByteArray data) {
        final int publicKeyByteCount;
        final PublicKey sendersPublicKey;
        if (_includePublicKey) {
            final ByteArray publicKeyBytes;
            if (Util.areEqual(PublicKey.UNCOMPRESSED_FIRST_BYTE, data.getByte(0))) {
                publicKeyBytes = ByteArray.wrap(data.getBytes(0, PublicKey.UNCOMPRESSED_BYTE_COUNT));
                publicKeyByteCount = PublicKey.UNCOMPRESSED_BYTE_COUNT;
            }
            else {
                publicKeyBytes = ByteArray.wrap(data.getBytes(0, PublicKey.COMPRESSED_BYTE_COUNT));
                publicKeyByteCount = PublicKey.COMPRESSED_BYTE_COUNT;
            }
            sendersPublicKey = PublicKey.fromBytes(publicKeyBytes).compress();
            if ((sendersPublicKey == null) || (! sendersPublicKey.isValid())) { return null; }

            final PublicKey publicKey = _localPrivateKey.getPublicKey();
            if ( (! Util.areEqual(publicKey.compress(), sendersPublicKey)) && (! Util.areEqual(_remotePublicKey.compress(), sendersPublicKey)) ) {
                return null;
            }
        }
        else {
            publicKeyByteCount = 0;
            sendersPublicKey = null; // _remotePublicKey;
        }

        final int hmacByteCount = 32;

        final ByteArray c;
        {
            final int cByteCount = (data.getByteCount() - publicKeyByteCount - hmacByteCount);
            c = ByteArray.wrap(data.getBytes(publicKeyByteCount, cByteCount));
        }

        final ByteArray d;
        {
            final int dOffset = (data.getByteCount() - hmacByteCount);
            d = Ecies.substring(data, dOffset);
        }

        final ByteArrayBuilder hmacPreImage = new ByteArrayBuilder();
        {
            final ByteArray initializationVector = ByteArray.wrap(c.getBytes(0, Aes.INITIALIZATION_VECTOR_BYTE_COUNT));
            final ByteArray ct = Ecies.substring(c, Aes.INITIALIZATION_VECTOR_BYTE_COUNT);

            hmacPreImage.appendBytes(initializationVector);
            if (_includePublicKey) {
                hmacPreImage.appendBytes(sendersPublicKey);
            }
            hmacPreImage.appendBytes(ct);
        }

        final ByteArray d2;
        {
            final PrivateKey kM = _getLastK();
            d2 = HashUtil.sha256Hmac(hmacPreImage, kM);
        }

        final boolean checksumMatches = Util.areEqual(d, d2);
        if (! checksumMatches) { return null; }

        final PrivateKey kE = _getFirstK();
        return Aes.decrypt(c, kE);
    }
}
