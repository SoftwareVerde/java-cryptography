package com.softwareverde.cryptography.secp256k1;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.secp256k1.signature.Secp256k1Signature;
import com.softwareverde.cryptography.secp256k1.signature.Signature;
import com.softwareverde.logging.Logger;
import com.softwareverde.util.HexUtil;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSAKCalculator;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.Security;

public class Secp256k1 {
    public static final ECCurve CURVE;
    public static final BigInteger CURVE_P;
    public static final BigInteger CURVE_N;
    public static final ECPoint CURVE_POINT_G;
    public static final ECDomainParameters CURVE_DOMAIN;

    static {
        Security.addProvider(new BouncyCastleProvider());

        final ECNamedCurveParameterSpec curveParameterSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
        CURVE_POINT_G = curveParameterSpec.getG();
        CURVE = curveParameterSpec.getCurve();
        CURVE_DOMAIN =  new ECDomainParameters(CURVE, CURVE_POINT_G, curveParameterSpec.getN());

        CURVE_P = new BigInteger(1, HexUtil.hexStringToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"));
        CURVE_N = new BigInteger(1, HexUtil.hexStringToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));
    }

    public static byte[] getPublicKeyPoint(final byte[] privateKeyBytes) {
        final ECPoint pointQ = Secp256k1.CURVE_POINT_G.multiply(new BigInteger(1, privateKeyBytes));
        return pointQ.getEncoded(false);
    }

    public static ByteArray getPublicKeyPoint(final ByteArray privateKey) {
        final ECPoint pointQ = Secp256k1.CURVE_POINT_G.multiply(new BigInteger(1, privateKey.getBytes()));
        return MutableByteArray.wrap(pointQ.getEncoded(false));
    }

    protected static Boolean _verifySignatureViaBouncyCastle(final Signature signature, final PublicKey publicKey, final byte[] message) {
        try {
            final ECPublicKeyParameters publicKeyParameters;
            {
                final ECPoint publicKeyPoint = Secp256k1.CURVE.decodePoint(publicKey.getBytes());
                publicKeyParameters = new ECPublicKeyParameters(publicKeyPoint, Secp256k1.CURVE_DOMAIN);
            }

            final ECDSASigner signer = new ECDSASigner();
            signer.init(false, publicKeyParameters);

            return signer.verifySignature(message, new BigInteger(1, signature.getR().getBytes()), new BigInteger(1, signature.getS().getBytes()));
        }
        catch (final Exception exception) {
            // NOTE: Bouncy Castle contains/contained a bug that would crash during certain specially-crafted malicious signatures.
            //  Instead of crashing, the signature is instead just marked as invalid.
            Logger.debug(exception);
            return false;
        }
    }

    public static Boolean verifySignature(final Signature signature, final PublicKey publicKey, final byte[] message) {
        // Fallback to BouncyCastle if the libsecp256k1 failed to load for this architecture...
        return _verifySignatureViaBouncyCastle(signature, publicKey, message);
    }

    /**
     * Signs the message with the provided PrivateKey.
     *  The `message` parameter is not hashed internally; therefore `message` should likely be a hash of the full message.
     *  The signature created is deterministic (as per RFC6979).
     */
    public static Secp256k1Signature sign(final PrivateKey privateKey, final byte[] message) {
        return Secp256k1.sign(privateKey, message, true);
    }

    /**
     * Signs the message with the provided PrivateKey.
     *  The `message` parameter is not hashed internally; therefore `message` should likely be a hash of the full message.
     *  A deterministic signature is created via HMAC-SHA256 (i.e. RFC6979) if `useDeterministicSignature` is set to true.
     */
    public static Secp256k1Signature sign(final PrivateKey privateKey, final byte[] message, final Boolean useDeterministicSignature) {
        final ECPrivateKeyParameters privateKeyParameters;
        {
            final BigInteger privateKeyBigInteger = new BigInteger(1, privateKey.getBytes());
            privateKeyParameters = new ECPrivateKeyParameters(privateKeyBigInteger, Secp256k1.CURVE_DOMAIN);
        }

        final DSAKCalculator kCalculator = new HMacDSAKCalculator(new SHA256Digest());
        final ECDSASigner signer = new ECDSASigner(kCalculator);
        signer.init(true, privateKeyParameters);

        final BigInteger r;
        final BigInteger s;
        {
            final BigInteger[] signatureIntegers = signer.generateSignature(message);
            r = signatureIntegers[0];
            s = signatureIntegers[1];
        }

        final byte[] rBytes = r.toByteArray();
        final byte[] sBytes;
        { // BIP-62: Reducing Transaction Malleability: https://github.com/bitcoin/bips/blob/master/bip-0062.mediawiki#Low_S_values_in_signatures
            // Since S may be positive or negative mod N, there are two valid signatures to a message.
            // In order to help eliminate transaction malleability, by convention, the S value will always be
            //  transformed to be the lower of its two possible values.
            // For instance, assume N is 10, and S is 8.  Another valid value for S could be 2 (i.e. -8 mod 10 == 2).
            //  The lower S can be calculated by taking N and subtracting S (i.e. 10 - 8 = 2).
            final BigInteger n = CURVE_DOMAIN.getN();
            if (s.compareTo(n.shiftRight(1)) <= 0) {
                sBytes = s.toByteArray();
            }
            else {
                sBytes = n.subtract(s).toByteArray();
            }
        }

        return new Secp256k1Signature(rBytes, sBytes);
    }

    public static byte[] decompressPoint(byte[] encodedPublicKeyPoint) {
        try {
            final ECPoint decodedPoint = CURVE.decodePoint(encodedPublicKeyPoint);

            final ECPoint normalizedPoint = decodedPoint.normalize();
            final BigInteger x = normalizedPoint.getXCoord().toBigInteger();
            final BigInteger y = normalizedPoint.getYCoord().toBigInteger();
            final ECPoint decompressedPoint = CURVE.createPoint(x, y);
            return decompressedPoint.getEncoded(false);
        }
        catch (final Exception exception) {
            Logger.trace("Unable to decompress point.", exception);
            return null;
        }
    }

    protected Secp256k1() { }
}
