package com.softwareverde.cryptography.rsa;

import com.softwareverde.cryptography.aes.AesKey;
import com.softwareverde.logging.Logger;
import com.softwareverde.logging.LoggerInstance;
import com.softwareverde.util.ByteUtil;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.bcpg.RSAPublicBCPGKey;
import org.bouncycastle.bcpg.RSASecretBCPGKey;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.crypto.signers.RSADigestSigner;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PrivateKeyInfoFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;

import java.io.IOException;

/**
 * <p>Encapsulates an RSA key pair.</p>
 *
 * <p>Provides methods for encrypting and signing data with RSA key pairs.  The keys are expected to be used for a single purpose.
 * An {@link RsaKeyMisuseException} will be thrown from methods that do not apply to the encapsulated keys.</p>
 *
 * <p>Largely intended for use with {@link com.softwareverde.cryptography.pgp.PgpKeys}.</p>
 */
public class BouncyCastleRsaKeys implements RsaKeys {
    private final LoggerInstance _logger = Logger.getInstance(getClass());

    private AsymmetricBlockCipher _cipher;
    private Signer _signer;
    private AsymmetricKeyParameter _publicKey;
    private AesKey _privateKeyEncryptionKey;
    private byte[] _privateKeyEncryptedBytes;

    private boolean _isEncryptionKeyPair;
    private boolean _isSigningKeyPair;

    public BouncyCastleRsaKeys(final PGPPublicKey publicKey, final PGPPrivateKey privateKey) {
        // track use of the keys and prevent using a key for the opposite purpose
        // as this has the possibility of being insecure and may impact our ability
        // to manage the keys separately in the future; it may also have legal implications:
        //
        //   https://crypto.stackexchange.com/q/12090/51716
        //   https://en.wikipedia.org/wiki/Digital_signature#Using_separate_key_pairs_for_signing_and_encryption
        //
        _isEncryptionKeyPair = publicKey.getAlgorithm() == PGPPublicKey.RSA_ENCRYPT;
        _isSigningKeyPair = publicKey.getAlgorithm() == PGPPublicKey.RSA_SIGN;

        _publicKey = _createPublicKey(publicKey);
        try {
            final RSAPrivateCrtKeyParameters privateKeyParameters = _createPrivateKey(privateKey);
            PrivateKeyInfo privateKeyInfo = PrivateKeyInfoFactory.createPrivateKeyInfo(privateKeyParameters);
            final byte[] rawPrivateKey = privateKeyInfo.toASN1Primitive().getEncoded();
            _encryptAndStorePrivateKey(rawPrivateKey);
            ByteUtil.cleanByteArray(rawPrivateKey);
        } catch (final Exception exception) {
            throw new RuntimeException("Unable to store private key information", exception);
        }

        _cipher = new OAEPEncoding(new RSAEngine());
        _signer = new RSADigestSigner(new SHA256Digest());
    }

    public BouncyCastleRsaKeys(final byte[] publicKey, final byte[] privateKey, final boolean isEncryptionKeyPair, final boolean isSigningKeyPair) throws IOException {
        _isEncryptionKeyPair = isEncryptionKeyPair;
        _isSigningKeyPair = isSigningKeyPair;

        // A KeyFactory is used to convert encoded keys to their actual Java classes
        try {
            _publicKey = PublicKeyFactory.createKey(publicKey);
            _encryptAndStorePrivateKey(privateKey);
        }
        catch (final Exception exception) {
            throw new IOException("Unable to convert keys", exception);
        }

        _cipher = new OAEPEncoding(new RSAEngine());
        _signer = new RSADigestSigner(new SHA256Digest());
    }

    @Override
    protected void finalize() {
        ByteUtil.cleanByteArray(_privateKeyEncryptedBytes);
    }

    protected void _encryptAndStorePrivateKey(final byte[] privateKeyBytes) {
        _privateKeyEncryptionKey = new AesKey();
        _privateKeyEncryptedBytes = _privateKeyEncryptionKey.encrypt(privateKeyBytes);
        ByteUtil.cleanByteArray(privateKeyBytes);
    }

    protected AsymmetricKeyParameter _getPrivateKey() {
        try {
            final byte[] privateKeyBytes = _privateKeyEncryptionKey.decrypt(_privateKeyEncryptedBytes);
            AsymmetricKeyParameter privateKey = PrivateKeyFactory.createKey(privateKeyBytes);
            ByteUtil.cleanByteArray(privateKeyBytes);
            return privateKey;
        } catch (IOException e) {
            throw new RuntimeException("Unable to access private key", e);
        }
    }

    private static RSAKeyParameters _createPublicKey(final PGPPublicKey pgpPublicKey) {
        final RSAPublicBCPGKey underlyingPublicKey = (RSAPublicBCPGKey) pgpPublicKey.getPublicKeyPacket().getKey();
        return new RSAKeyParameters(
                    false,
                    underlyingPublicKey.getModulus(),
                    underlyingPublicKey.getPublicExponent());
    }

    private static RSAPrivateCrtKeyParameters _createPrivateKey(final PGPPrivateKey pgpPrivateKey) {
        RSASecretBCPGKey underlyingPrivateKey = (RSASecretBCPGKey) pgpPrivateKey.getPrivateKeyDataPacket();
        RSAPublicBCPGKey underlyingPublicKey = (RSAPublicBCPGKey) pgpPrivateKey.getPublicKeyPacket().getKey();
        return new RSAPrivateCrtKeyParameters(
                underlyingPrivateKey.getModulus(),
                underlyingPublicKey.getPublicExponent(),
                underlyingPrivateKey.getPrivateExponent(),
                underlyingPrivateKey.getPrimeP(),
                underlyingPrivateKey.getPrimeQ(),
                underlyingPrivateKey.getPrimeExponentP(),
                underlyingPrivateKey.getPrimeExponentQ(),
                underlyingPrivateKey.getCrtCoefficient());
    }

    public byte[] getPublicKey() {
        try {
            RSAKeyParameters publicKey = ((RSAKeyParameters) _publicKey);
            RSAPublicKey rsaPublicKey = new RSAPublicKey(publicKey.getModulus(), publicKey.getExponent());
            return rsaPublicKey.getEncoded();
        } catch (final Exception exception) {
            _logger.error("Unable to get public key bytes", exception);
            return null;
        }
    }

    /**
     * <p>Provides a mechanism for encrypting data with a public key when the private key is not available.
     * For example, this enables encrypting data with another user's public key.</p>
     *
     * @param publicKey
     * @param plainText
     * @return Returns the encryption data.
     */
    public static byte[] encryptWithPublicKey(final PGPPublicKey publicKey, final byte[] plainText) {
        if (publicKey.getAlgorithm() != PGPPublicKey.RSA_ENCRYPT) {
            throw new RsaKeyMisuseException("Attempt to encrypt using an non-encryption public key.");
        }

        try {
            AsymmetricKeyParameter underlyingPublicKey = _createPublicKey(publicKey);
            AsymmetricBlockCipher cipher = new OAEPEncoding(new RSAEngine());

            cipher.init(true, underlyingPublicKey);
            return cipher.processBlock(plainText, 0, plainText.length);
        }
        catch (final Exception exception) {
            Logger.error("Unable to encrypt data", exception);
            return null;
        }
    }

    /**
     * <p>Encrypts the provided data with the internally stored public key.</p>
     * @param plainText
     * @return Returns the encrypted cipher-text data.
     */
    public synchronized byte[] encrypt(final byte[] plainText) {
        if (!_isEncryptionKeyPair) {
            throw new RsaKeyMisuseException("Attempt to encrypt using an non-encryption public key.");
        }

        try {
            _cipher.init(true, _publicKey);
            return _cipher.processBlock(plainText, 0, plainText.length);
        }
        catch (final Exception exception) {
            _logger.error("Unable to encrypt data", exception);
            return null;
        }
    }

    /**
     * <p>Decrypts the provided data with the internally stored private key.</p>
     * @param cipherText
     * @return Returns the decrypted plain-text data.
     */
    public synchronized byte[] decrypt(final byte[] cipherText) {
        if (!_isEncryptionKeyPair) {
            throw new RsaKeyMisuseException("Attempt to decrypt using an non-encryption private key.");
        }

        try {
            _cipher.init(false, _getPrivateKey());
            return _cipher.processBlock(cipherText, 0, cipherText.length);
        }
        catch (final Exception exception) {
            _logger.error("Unable to decrypt data", exception);
            return null;
        }
    }

    /**
     * <p>Signs the provided data with the internally stored private key using a SHA256 hash.</p>
     * @param data
     * @return The signature, without the original data.
     */
    public synchronized byte[] sign(final byte[] data) {
        if (!_isSigningKeyPair) {
            throw new RsaKeyMisuseException("Attempt to sign using an non-signature private key.");
        }

        try {
            _signer.init(true, _getPrivateKey());
            _signer.update(data, 0, data.length);
            byte[] signature = _signer.generateSignature();
            return signature;
        }
        catch (final Exception exception) {
            _logger.error("Unable to sign data", exception);
            return null;
        }
    }

    /**
     * <p>Verifies the provided data with the given signature and public key.</p>
     * @param data
     * @param signature
     * @return True iff re-signing the data with the public key matches the signature.
     */
    public static boolean verifyWithPublicKey(final PGPPublicKey publicKey, final byte[] data, final byte[] signature) {
        if (publicKey.getAlgorithm() != PGPPublicKey.RSA_SIGN) {
            throw new RsaKeyMisuseException("Attempt to verify signature using an non-signature public key.");
        }

        try {
            AsymmetricKeyParameter underlyingPublicKey = _createPublicKey(publicKey);
            final Signer signer = new RSADigestSigner(new SHA256Digest());

            signer.init(false, underlyingPublicKey);
            signer.update(data, 0, data.length);
            return signer.verifySignature(signature);
        }
        catch (final Exception exception) {
            Logger.error("Unable to verify signature", exception);
            return false;
        }
    }

    /**
     * <p>Verifies the provided data with the given signature and internal public key.</p>
     * @param data
     * @param signature
     * @return True iff re-signing the provided data with the internal key matches the provided signature.
     */
    public synchronized boolean verify(final byte[] data, final byte[] signature) {
        if (!_isSigningKeyPair) {
            throw new RsaKeyMisuseException("Attempt to verify signature using an non-signature public key.");
        }

        try {
            _signer.init(false, _publicKey);
            _signer.update(data, 0, data.length);
            return _signer.verifySignature(signature);
        }
        catch (final Exception exception) {
            _logger.error("Unable to verify signature", exception);
            return false;
        }
    }
}
