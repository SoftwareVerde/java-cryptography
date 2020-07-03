package com.softwareverde.cryptography.secp256k1.ecies;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.hash.sha512.Sha512Hash;
import com.softwareverde.cryptography.secp256k1.Secp256k1;
import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.logging.Logger;
import com.softwareverde.util.bytearray.ByteArrayBuilder;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.spec.AlgorithmParameterSpec;

public class EciesUtil {
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
                Logger.debug("Unable to encrypt data.", exception);
                return null;
            }
        }

        public static ByteArray decrypt(final ByteArray data, final ByteArray key) {
            try {
                final SecretKey secretKey = new SecretKeySpec(key.getBytes(), 0, key.getByteCount(), KEY_ALGORITHM);

                final byte[] initializationVectorBytes = data.getBytes(0, INITIALIZATION_VECTOR_BYTE_COUNT);
                final AlgorithmParameterSpec initializationVector = new IvParameterSpec(initializationVectorBytes);
                final ByteArray encryptedData = EciesUtil.substring(data, INITIALIZATION_VECTOR_BYTE_COUNT);

                final Cipher aesCipher = Cipher.getInstance(ENCRYPTION_CIPHER);
                aesCipher.init(Cipher.DECRYPT_MODE, secretKey, initializationVector);
                return ByteArray.wrap(aesCipher.doFinal(encryptedData.getBytes()));
            }
            catch (final Exception exception) {
                Logger.debug("Unable to decrypt data.", exception);
                return null;
            }
        }
    }

    public static Sha512Hash getK(final PublicKey publicKey, final PrivateKey privateKey) {
        final ECCurve curve = Secp256k1.CURVE_DOMAIN.getCurve();
        final PublicKey decompressedPublicKey = publicKey.decompress();
        final ECPoint KB = curve.decodePoint(decompressedPublicKey.getBytes());
        final ECPoint P = KB.multiply(new BigInteger(1, privateKey.getBytes()));
        final BigInteger S = P.normalize().getXCoord().toBigInteger();
        final MutableByteArray sBytes = new MutableByteArray(32);
        sBytes.setBytes(0, S.toByteArray());

        return HashUtil.sha512(sBytes);
    }

    public static PrivateKey getFirstK(final PublicKey publicKey, final PrivateKey privateKey) {
        final Sha512Hash k = getK(publicKey, privateKey);
        return PrivateKey.fromBytes(k.getBytes(0, PrivateKey.KEY_BYTE_COUNT));
    }

    public static PrivateKey getLastK(final PublicKey publicKey, final PrivateKey privateKey) {
        final Sha512Hash k = getK(publicKey, privateKey);
        return PrivateKey.fromBytes(EciesUtil.substring(k, PrivateKey.KEY_BYTE_COUNT));
    }
}
