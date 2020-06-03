package com.softwareverde.cryptography.pgp;

import com.softwareverde.logging.Logger;
import com.softwareverde.cryptography.rsa.BouncyCastleRsaKeys;
import com.softwareverde.cryptography.rsa.RsaKeys;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.*;

import java.io.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Date;
import java.util.Iterator;

/**
 * <p>Provides mechanisms for generating, loading, and using PGP keys.</p>
 *
 * <p>Based on code found <a href="http://sloanseaman.com/wordpress/2012/05/13/revisited-pgp-encryptiondecryption-in-java/">here</a>
 * and <a href="https://bouncycastle-pgp-cookbook.blogspot.com/">here</a>.</p>
 */
public class PgpKeys {
    private static final BigInteger RSA_PUBLIC_EXPONENT = BigInteger.valueOf(0x10001); // 2^16 + 1
    private static final int RSA_KEY_LENGTH = 4096;
    private static final int RSA_S2K_COUNT = 192; // ~130,000 hash iterations
    private static final int RSA_CERTAINTY = 12;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private PGPPublicKeyRing _publicKeyRing;
    private PGPSecretKeyRing _secretKeyRing;

    /**
     * <p>Attempts to load PGP keys from disk.</p>
     */
    public PgpKeys(final File configurationDirectory) throws IOException, PGPException {
        final File publicKeyPath = _getPublicKeyPath(configurationDirectory);
        final File privateKeyPath = _getPrivateKeyPath(configurationDirectory);

        try (FileInputStream publicKeyRingInputStream = new FileInputStream(publicKeyPath);
             FileInputStream secretKeyRingInputStream = new FileInputStream(privateKeyPath)) {
            _init(publicKeyRingInputStream, secretKeyRingInputStream);
        }
    }

    /**
     * Created an object that only contains the public key ring.  Used when accessing another person's keys.
     * @param publicKeyRingData
     */
    public PgpKeys(final byte[] publicKeyRingData) throws IOException {
        final ByteArrayInputStream publicKeyRingInputStream = new ByteArrayInputStream(publicKeyRingData);
        _publicKeyRing = new PGPPublicKeyRing(publicKeyRingInputStream, new BcKeyFingerprintCalculator());
    }

    public PgpKeys(final byte[] publicKeyRingData, final byte[] secretKeyRingData) throws IOException, PGPException {
        _init(new ByteArrayInputStream(publicKeyRingData), new ByteArrayInputStream(secretKeyRingData));
    }

    protected void _init(final InputStream publicKeyRingInputStream, final InputStream secretKeyRingInputStream) throws IOException, PGPException {
        _publicKeyRing = new PGPPublicKeyRing(publicKeyRingInputStream, new BcKeyFingerprintCalculator());
        _secretKeyRing = new PGPSecretKeyRing(secretKeyRingInputStream, new BcKeyFingerprintCalculator());
    }

    /**
     * <p>Creates a new set of PGP key rings with the provided ID.  The secret key ring will be encrypted with the provided password.</p>
     * @param id
     * @param password
     * @throws PGPException
     * @throws IOException
     */
    public PgpKeys(final String id, final char[] password) throws PGPException, IOException {
        this(id, password, false, null);
    }

    /**
     * <p>Creates a new set of PGP key rings with the provided ID.  The secret key ring will be encrypted with the provided password and stored in the specified configuration directory.</p>
     * @param id
     * @param password
     * @param configurationDirectory
     * @throws PGPException
     * @throws IOException
     */
    public PgpKeys(final String id, final char[] password, final File configurationDirectory) throws PGPException, IOException {
        this(id, password, true, configurationDirectory);
    }

    public PgpKeys(final String id, final char[] password, final boolean shouldStoreKeys, final File configurationDirectory) throws PGPException, IOException {
        PGPKeyRingGenerator pgpKeyRingGenerator = generateKeyRingGenerator(id, password);

        _publicKeyRing = pgpKeyRingGenerator.generatePublicKeyRing();
        _secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();

        if (shouldStoreKeys) {
            store(configurationDirectory);
        }
    }

    protected static File _getPublicKeyPath(final File configurationDirectory) {
        return new File(configurationDirectory.getAbsolutePath() + File.separator + "doc-chain.pkr");
    }

    protected static File _getPrivateKeyPath(final File configurationDirectory) {
        return new File(configurationDirectory.getAbsolutePath() + File.separator + "doc-chain.skr");
    }

    public void store(final File configurationDirectory) throws IOException {
        final File publicKeyPath = _getPublicKeyPath(configurationDirectory);
        final File privateKeyPath = _getPrivateKeyPath(configurationDirectory);

        try (FileOutputStream publicKeyRingOutputStream = new FileOutputStream(publicKeyPath);
             FileOutputStream secretKeyRingOutputStream = new FileOutputStream(privateKeyPath)) {
            _publicKeyRing.encode(publicKeyRingOutputStream);
            _secretKeyRing.encode(secretKeyRingOutputStream);
        }
        catch (final Exception exception) {
            Logger.error("Unable to store PGP keys", exception);
            throw new IOException(exception);
        }
    }

    public static void clear(final File configurationDirectory) {
        final File publicKeyPath = _getPublicKeyPath(configurationDirectory);
        final File privateKeyPath = _getPrivateKeyPath(configurationDirectory);
        try {
            boolean success = publicKeyPath.delete();
            if (! success) {
                throw new IOException("Unable to delete public key file: " + publicKeyPath.getAbsolutePath());
            }
            success = privateKeyPath.delete();
            if (! success) {
                throw new IOException("Unable to delete private key file: " + privateKeyPath.getAbsolutePath());
            }
        }
        catch (final Exception exception) {
            Logger.error("Unable to delete local PGP keys", exception);
        }
    }

    /**
     * <p>Checks for PGP keys at the specified directory and returns true if both the public and private keyrings are present.</p>
     *
     * <p>Alternately, returns true if the specified directory is null, as it is assumed that the PGP keys are not stored on disk
     * and are therefore always available.</p>
     */
    public static boolean doLocalPgpKeysExist(final File configurationDirectory) {
        if (configurationDirectory == null) {
            return true;
        }

        final File publicKeyPath = _getPublicKeyPath(configurationDirectory);
        final File privateKeyPath = _getPrivateKeyPath(configurationDirectory);

        return (publicKeyPath.exists() && privateKeyPath.exists());
    }

    public void generateAndStoreKeyRingsForNewPassword(final String id, final char[] currentPassword, final char[] newPassword) throws PGPException, IOException {
        final PGPKeyRingGenerator pgpKeyRingGenerator = generateKeyRingGeneratorForNewPassword(id, currentPassword, newPassword);

        // A new public key ring is not generated because it is not necessary to complete the password change process.
        // Additionally, storing the newly generated public key could cause issues with shared documents.
        _secretKeyRing = pgpKeyRingGenerator.generateSecretKeyRing();
    }

    private PGPKeyRingGenerator generateKeyRingGeneratorForNewPassword(final String id, final char[] currentPassword, final char[] newPassword) throws PGPException {
        PGPKeyPair signatureKeyPair = null;
        PGPKeyPair encryptionKeyPair = null;

        for (Iterator<PGPSecretKey> it = _secretKeyRing.getSecretKeys(); it.hasNext(); ) {
            final PGPSecretKey secretKey = it.next();
            PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(currentPassword);
            PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);

            if (secretKey.getPublicKey().getAlgorithm() == PublicKeyAlgorithmTags.RSA_SIGN) {
                signatureKeyPair = new PGPKeyPair(secretKey.getPublicKey(), privateKey);
            }
            else if (secretKey.getPublicKey().getAlgorithm() == PublicKeyAlgorithmTags.RSA_ENCRYPT) {
                encryptionKeyPair = new PGPKeyPair(secretKey.getPublicKey(), privateKey);
            }
        }

        if ((signatureKeyPair == null) || (encryptionKeyPair == null)) {
            throw new IllegalStateException("Unable to find both matching key pairs.");
        }

        PGPKeyRingGenerator keyRingGenerator = _createSelfSignedKeyRingGenerator(signatureKeyPair, id, newPassword);
        _signAndAddEncryptionKeyPair(keyRingGenerator, encryptionKeyPair);

        return keyRingGenerator;
    }

    private static PGPKeyRingGenerator generateKeyRingGenerator(final String id, final char[] password) throws PGPException {
        RSAKeyGenerationParameters rsaKeyGenerationParameters = new RSAKeyGenerationParameters(RSA_PUBLIC_EXPONENT, new SecureRandom(), RSA_KEY_LENGTH, RSA_CERTAINTY);

        RSAKeyPairGenerator rsaKeyPairGenerator = new RSAKeyPairGenerator();
        rsaKeyPairGenerator.init(rsaKeyGenerationParameters);

        PGPKeyPair signatureKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_SIGN, rsaKeyPairGenerator.generateKeyPair(), new Date());
        PGPKeyPair encryptionKeyPair = new BcPGPKeyPair(PGPPublicKey.RSA_ENCRYPT, rsaKeyPairGenerator.generateKeyPair(), new Date());

        PGPKeyRingGenerator keyRingGenerator = _createSelfSignedKeyRingGenerator(signatureKeyPair, id, password);
        _signAndAddEncryptionKeyPair(keyRingGenerator, encryptionKeyPair);

        return keyRingGenerator;
    }

    private static PGPKeyRingGenerator _createSelfSignedKeyRingGenerator(final PGPKeyPair signatureKeyPair, final String id, final char[] password) throws PGPException {
        PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
        signatureSubpacketGenerator.setKeyFlags(false, KeyFlags.SIGN_DATA | KeyFlags.CERTIFY_OTHER);
        signatureSubpacketGenerator.setPreferredSymmetricAlgorithms(false, new int[]{
                SymmetricKeyAlgorithmTags.AES_256,
                SymmetricKeyAlgorithmTags.AES_192,
                SymmetricKeyAlgorithmTags.AES_128
        });
        signatureSubpacketGenerator.setPreferredHashAlgorithms(false, new int[]{
                HashAlgorithmTags.SHA256,
                HashAlgorithmTags.SHA512,
                HashAlgorithmTags.SHA384,
                HashAlgorithmTags.SHA224
        });
        // request additional checksums on messages
        signatureSubpacketGenerator.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

        PGPDigestCalculator sha256Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA256);
        BcPBESecretKeyEncryptorBuilder secretKeyEncryptorBuilder = new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_256, sha256Calc, RSA_S2K_COUNT);
        PBESecretKeyEncryptor secretKeyEncryptor = secretKeyEncryptorBuilder.build(password);

        PGPSignatureSubpacketVector signatureSubpacketVector = signatureSubpacketGenerator.generate();

        // SHA-1 is apparently required here by the PGP standard
        // See:
        //      http://bouncy-castle.1462172.n4.nabble.com/SHA-1-Collision-is-it-okay-to-use-for-checksum-td4658560.html#a4658566
        //
        PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
        BcPGPContentSignerBuilder contentSignerBuilder = new BcPGPContentSignerBuilder(signatureKeyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
        PGPKeyRingGenerator keyRingGenerator = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, signatureKeyPair, id, sha1Calc, signatureSubpacketVector, null, contentSignerBuilder, secretKeyEncryptor);
        return keyRingGenerator;
    }

    private static void _signAndAddEncryptionKeyPair(final PGPKeyRingGenerator keyRingGenerator, final PGPKeyPair encryptionKeyPair) throws PGPException {
        PGPSignatureSubpacketGenerator signatureSubpacketGenerator = new PGPSignatureSubpacketGenerator();
        signatureSubpacketGenerator.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

        PGPSignatureSubpacketVector encryptionSubpacketVector = signatureSubpacketGenerator.generate();
        keyRingGenerator.addSubKey(encryptionKeyPair, encryptionSubpacketVector, null);
    }

    public RsaKeys getRsaSigningKeys(final char[] password) throws PGPException {
        return _extractRsaKeyPair(password, PGPPublicKey.RSA_SIGN);
    }

    public RsaKeys getRsaEncryptionKeys(final char[] password) throws PGPException {
        return _extractRsaKeyPair(password, PGPPublicKey.RSA_ENCRYPT);
    }

    protected RsaKeys _extractRsaKeyPair(final char[] password, final int algorithm) throws PGPException {
        for (Iterator<PGPSecretKey> it = _secretKeyRing.getSecretKeys(); it.hasNext(); ) {
            final PGPSecretKey secretKey = it.next();
            if (secretKey.getPublicKey().getAlgorithm() == algorithm) {
                PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(password);
                PGPPrivateKey privateKey = secretKey.extractPrivateKey(decryptor);
                return new BouncyCastleRsaKeys(secretKey.getPublicKey(), privateKey);
            }
        }
        throw new IllegalStateException("Unable to find matching key pair for algorithm: " + algorithm);
    }

    public PGPPublicKeyRing getPublicKeyRing() {
        return _publicKeyRing;
    }

    public PGPPublicKey getEncryptionKey() {
        return _getPublicKey(PGPPublicKey.RSA_ENCRYPT);
    }

    public PGPPublicKey getSignatureVerificationKey() {
        return _getPublicKey(PGPPublicKey.RSA_SIGN);
    }

    public PGPSecretKeyRing getSecretKeyRing() {
        return _secretKeyRing;
    }

    protected PGPPublicKey _getPublicKey(final int algorithm) {
        for (Iterator<PGPPublicKey> it = _publicKeyRing.getPublicKeys(); it.hasNext(); ) {
            final PGPPublicKey publicKey = it.next();
            if (publicKey.getAlgorithm() == algorithm) {
                return publicKey;
            }
        }
        throw new IllegalStateException("Unable to find public key for algorithm: " + algorithm);
    }

    public byte[] rsaEncrypt(final byte[] plainText) {
        return BouncyCastleRsaKeys.encryptWithPublicKey(getEncryptionKey(), plainText);
    }

    public byte[] rsaDecrypt(final byte[] cipherText, final char[] password) throws PGPException {
        RsaKeys rsaKeys = getRsaEncryptionKeys(password);
        return rsaKeys.decrypt(cipherText);
    }

    public byte[] rsaSign(final byte[] data, final char[] password) throws PGPException {
        RsaKeys rsaKeys = getRsaSigningKeys(password);
        return rsaKeys.sign(data);
    }

    public boolean rsaVerify(final byte[] data, final byte[] signature) {
        return BouncyCastleRsaKeys.verifyWithPublicKey(getSignatureVerificationKey(), data, signature);
    }

    public boolean hasMatchingPublicKeys(final PgpKeys pgpKeys) throws IOException {
        return pgpKeys != null
                && Arrays.equals(this.getEncryptionKey().getEncoded(), pgpKeys.getEncryptionKey().getEncoded())
                && Arrays.equals(this.getSignatureVerificationKey().getEncoded(), pgpKeys.getSignatureVerificationKey().getEncoded());
    }
}
