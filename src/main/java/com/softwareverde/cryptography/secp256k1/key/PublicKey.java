package com.softwareverde.cryptography.secp256k1.key;

import com.softwareverde.constable.Const;
import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.ImmutableByteArray;
import com.softwareverde.cryptography.hash.sha256.Sha256Hash;
import com.softwareverde.cryptography.secp256k1.Secp256k1;
import com.softwareverde.cryptography.secp256k1.signature.Signature;
import com.softwareverde.logging.Logger;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.HexUtil;
import org.bouncycastle.math.ec.ECAlgorithms;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class PublicKey extends ImmutableByteArray implements Const {
    public static final byte UNCOMPRESSED_FIRST_BYTE = (byte) 0x04;
    public static final byte COMPRESSED_FIRST_BYTE_0 = (byte) 0x02;
    public static final byte COMPRESSED_FIRST_BYTE_1 = (byte) 0x03;

    public static final Integer COMPRESSED_BYTE_COUNT = 33;
    public static final Integer UNCOMPRESSED_BYTE_COUNT = 65;

    public static PublicKey fromBytes(final byte[] bytes) {
        if (bytes == null) { return null; }

        return new PublicKey(bytes);
    }

    public static PublicKey fromBytes(final ByteArray bytes) {
        if (bytes == null) { return null; }

        return new PublicKey(bytes);
    }

    public static PublicKey fromHexString(final String hexString) {
        if (hexString == null) { return null; }

        final byte[] byteArray = HexUtil.hexStringToByteArray(hexString);
        if (byteArray == null) { return null; }

        final PublicKey publicKey = new PublicKey(byteArray);
        if (! publicKey.isValid()) { return null; }

        return publicKey;
    }

    /**
     * Determine the public key used from a signed message.
     *  This algorithm operation is described in sec1-v2, section 4.1.6: https://www.secg.org/sec1-v2.pdf
     *  The `recoveryIndex` takes the place of the `j` and `k` variables in the specification, allowing the calling
     *  function to either provide a known recovery ID or iterate through the possibilities (0-3) to find a public key
     *  candidate that meets criteria known to the caller.
     */
    public static PublicKey fromSignature(final Signature signature, final Sha256Hash messagePreImage, final Integer recoveryIndex) {
        final ECCurve curve = Secp256k1.CURVE_DOMAIN.getCurve();
        final BigInteger n = Secp256k1.CURVE_DOMAIN.getN();  // Curve order.
        final BigInteger r = new BigInteger(1, signature.getR().getBytes());
        final BigInteger s = new BigInteger(1, signature.getS().getBytes());

        //   1.1 Let x = r + jn
        final BigInteger i = BigInteger.valueOf(recoveryIndex / 2L);
        final BigInteger x = r.add(i.multiply(n));

        // 1.2. Convert the integer x to an octet string X of length mlen using the conversion routine
        //      specified in Section 2.3.7, where mlen = d(log2 p)/8e or mlen = dm/8e.
        // 1.3. Convert the octet string 0216kX to an elliptic curve point R using the conversion routine
        //      specified in Section 2.3.4. If this conversion routine outputs "invalid", then do another
        //      iteration of Step 1.
        if (x.compareTo(Secp256k1.CURVE_P) >= 0) { return null; } // Public key is not on the curve.

        final byte[] compressedPoint = new byte[32 + 1];
        {
            final boolean yCoordinateIsEven = ((recoveryIndex & 0x01) == 0x00);

            final byte[] xPointBytes = x.toByteArray();
            compressedPoint[0] = (byte) (yCoordinateIsEven ? 0x02 : 0x03);
            ByteUtil.setBytes(compressedPoint, ByteUtil.getTailBytes(xPointBytes, 32), 1);
        }

        final byte[] decompressedPublicKeyBytes = Secp256k1.decompressPoint(compressedPoint);
        if (decompressedPublicKeyBytes == null) { return null; }

        final ECPoint publicKeyPoint = curve.decodePoint(decompressedPublicKeyBytes);

        // 1.4. If nR != infinity, then do another iteration of Step 1.
        if (! publicKeyPoint.multiply(n).isInfinity()) { return null; }

        // 1.5. Compute e from M using Steps 2 and 3 of ECDSA signature verification.
        final BigInteger e = new BigInteger(1, messagePreImage.getBytes());

        // 1.6. For k from 1 to 2 do the following.
        //   1.6.1. Compute a candidate public key as:
        //          Q = r^(−1)(sR − eG)

        // Thanks to Google/Andreas Schildbach:
        //      Q = r^(−1)(sR − eG) = mi(r) * (sR - eG)
        // Where mi(x) is the modular multiplicative inverse.
        // Therefore, Q = (mi(r) * s ** R) + (mi(r) * -e ** G)
        // Where -e is the modular additive inverse of e, that is z such that z + e = 0 (mod n).
        // Where "**" and "+" is EC maths, aka point multiplication and point addition, respectively.
        //
        // To find the additive inverse, subtract e from zero then take the mod.
        // For example, the additive inverse of 3 modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.

        final BigInteger eInverse = BigInteger.ZERO.subtract(e).mod(n);
        final BigInteger rInverse = r.modInverse(n);
        final BigInteger srInverse = rInverse.multiply(s).mod(n);
        final BigInteger eInverseTimesRInverseModN = rInverse.multiply(eInverse).mod(n);
        final ECPoint q = ECAlgorithms.sumOfTwoMultiplies(Secp256k1.CURVE_DOMAIN.getG(), eInverseTimesRInverseModN, publicKeyPoint, srInverse);

        final byte[] publicKeyBytes = q.getEncoded(false);
        if (publicKeyBytes.length == 1) { return null; }

        return new PublicKey(publicKeyBytes);
    }

    protected Boolean _isCompressed() {
        if (_bytes.length != COMPRESSED_BYTE_COUNT) { return false; }

        final byte firstByte = _bytes[0];
        return ( (firstByte == COMPRESSED_FIRST_BYTE_0) || (firstByte == COMPRESSED_FIRST_BYTE_1) );
    }

    protected Boolean _isDecompressed() {
        if (_bytes.length != UNCOMPRESSED_BYTE_COUNT) { return false; }

        final byte firstByte = _bytes[0];
        return (firstByte == UNCOMPRESSED_FIRST_BYTE);
    }

    protected PublicKey(final byte[] bytes) {
        super(bytes);
    }

    protected PublicKey(final ByteArray byteArray) {
        super(byteArray);
    }

    public Boolean isCompressed() {
        return _isCompressed();
    }

    public Boolean isDecompressed() {
        return _isDecompressed();
    }

    public PublicKey decompress() {
        if (_bytes.length == 0) { return this; } // NOP
        if (_isDecompressed()) { return this; }

        final byte[] decompressedBytes = Secp256k1.decompressPoint(_bytes);
        if (decompressedBytes == null) {
            Logger.warn("Unable to decompress PublicKey.");
            return null;
        }

        decompressedBytes[0] = (byte) 0x04;
        return new PublicKey(decompressedBytes);
    }

    public PublicKey compress() {
        if (_bytes.length == 0) { return this; } // NOP
        if (_isCompressed()) { return this; }

        final int coordinateByteCount = ((_bytes.length - 1) / 2);

        final int prefixByteCount = 1;
        // final byte prefix = _bytes[0];
        final byte[] publicKeyPointX = new byte[coordinateByteCount];
        final byte[] publicKeyPointY = new byte[coordinateByteCount];
        {
            for (int i = 0; i < coordinateByteCount; ++i) {
                publicKeyPointX[i] = _bytes[prefixByteCount + i];
                publicKeyPointY[i] = _bytes[prefixByteCount + coordinateByteCount + i];
            }
        }
        final boolean yCoordinateIsEven = ((publicKeyPointY[coordinateByteCount - 1] & 0xFF) % 2 == 0);
        final byte compressedPublicKeyPrefix = (yCoordinateIsEven ? (byte) 0x02 : (byte) 0x03);
        final byte[] compressedPublicKeyPoint = new byte[coordinateByteCount + prefixByteCount];
        {
            compressedPublicKeyPoint[0] = compressedPublicKeyPrefix;
            for (int i = 0; i < publicKeyPointX.length; ++i) {
                compressedPublicKeyPoint[prefixByteCount + i] = publicKeyPointX[i];
            }
        }

        return new PublicKey(compressedPublicKeyPoint);
    }

    public Boolean isValid() {
        return (_isCompressed() || _isDecompressed());
    }

    @Override
    public PublicKey asConst() {
        return this;
    }
}