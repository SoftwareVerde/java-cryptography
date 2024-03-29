package com.softwareverde.cryptography.secp256k1;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.hash.sha256.Sha256Hash;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.bytearray.ByteArrayBuilder;
import com.softwareverde.util.bytearray.Endian;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECFieldElement;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;

public class EcMultiset {
    // https://arxiv.org/pdf/1601.06502.pdf
    // https://github.com/tomasvdw/bips/blob/master/ecmh.mediawiki

    protected static ECPoint convertToPoint(final BigInteger x) {
        if (x.compareTo(Secp256k1.CURVE_P) >= 0) { return null; } // Public key is not on the curve.

        final int byteCount = 32;
        final byte[] encodedCompressedPoint = new byte[byteCount + 1];
        {
            final byte[] xPointBytes = x.toByteArray();
            final boolean yCoordinateIsEven = (! ByteUtil.getBit(xPointBytes, 0));
            encodedCompressedPoint[0] = (yCoordinateIsEven ? PublicKey.COMPRESSED_FIRST_BYTE_0 : PublicKey.COMPRESSED_FIRST_BYTE_1);
            ByteUtil.setBytes(encodedCompressedPoint, ByteUtil.getTailBytes(xPointBytes, byteCount), 1);
        }

        final byte[] decompressedPublicKeyBytes = Secp256k1.decompressPoint(encodedCompressedPoint);
        if (decompressedPublicKeyBytes == null) { return null; }

        final ECCurve curve = Secp256k1.CURVE_DOMAIN.getCurve();
        return curve.decodePoint(decompressedPublicKeyBytes);
    }

    protected static ECPoint getPoint(final Sha256Hash byteArrayHash) {
        long n = 0L;
        while (true) {
            final ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder();
            byteArrayBuilder.appendBytes(ByteArray.wrap(ByteUtil.longToBytes(n)), Endian.LITTLE);
            byteArrayBuilder.appendBytes(byteArrayHash, Endian.BIG);

            final Sha256Hash xBytes = HashUtil.sha256(byteArrayBuilder);

            final ECPoint ecPoint = EcMultiset.convertToPoint(new BigInteger(1, xBytes.getBytes()));
            if (ecPoint != null) {
                return ecPoint;
            }

            n += 1L;
        }
    }

    protected static ECPoint getPoint(final PublicKey publicKey) {
        final PublicKey decompressedPublicKey = publicKey.decompress();
        if (decompressedPublicKey == null) {
            return Secp256k1.CURVE.getInfinity(); // PublicKey was at infinity.
        }

        final ECCurve curve = Secp256k1.CURVE_DOMAIN.getCurve();
        return curve.decodePoint(decompressedPublicKey.getBytes());
    }

    protected ECPoint _point;

    public EcMultiset() {
        _point = Secp256k1.CURVE.getInfinity();
    }

    public EcMultiset(final PublicKey publicKey) {
        _point = EcMultiset.getPoint(publicKey);
    }

    public void add(final EcMultiset ecMultiset) {
        final ECPoint multisetPoint = ecMultiset._point;

        synchronized (this) {
            _point = _point.add(multisetPoint).normalize();
        }
    }

    public void add(final PublicKey multisetHashPublicKey) {
        final ECPoint multisetPoint = EcMultiset.getPoint(multisetHashPublicKey);

        synchronized (this) {
            _point = _point.add(multisetPoint).normalize();
        }
    }

    public void addItem(final ByteArray byteArray) {
        final Sha256Hash byteArrayHash = HashUtil.sha256(byteArray);
        final ECPoint point = EcMultiset.getPoint(byteArrayHash);

        synchronized (this) {
            _point = _point.add(point).normalize();
        }
    }

    public void removeItem(final ByteArray byteArray) {
        final Sha256Hash byteArrayHash = HashUtil.sha256(byteArray);
        final ECPoint point = EcMultiset.getPoint(byteArrayHash);

        synchronized (this) {
            _point = _point.subtract(point).normalize();
        }
    }

    public Sha256Hash getHash() {
        final ECFieldElement xCoordinate;
        final ECFieldElement yCoordinate;
        synchronized (this) {
            if (_point.isInfinity()) { return Sha256Hash.EMPTY_HASH; }

            xCoordinate = _point.getXCoord();
            yCoordinate = _point.getYCoord();
        }

        final BigInteger xBigInteger = xCoordinate.toBigInteger();
        final BigInteger yBigInteger = yCoordinate.toBigInteger();

        final ByteArrayBuilder byteArrayBuilder = new ByteArrayBuilder();
        byteArrayBuilder.appendBytes(ByteUtil.getTailBytes(xBigInteger.toByteArray(), Sha256Hash.BYTE_COUNT));
        byteArrayBuilder.appendBytes(ByteUtil.getTailBytes(yBigInteger.toByteArray(), Sha256Hash.BYTE_COUNT));

        return HashUtil.sha256(byteArrayBuilder);
    }

    public PublicKey getPublicKey() {
        final byte[] encodedBytes = _point.getEncoded(true);
        final int offset = (PublicKey.COMPRESSED_BYTE_COUNT - encodedBytes.length);
        final MutableByteArray compressedBytes = new MutableByteArray(PublicKey.COMPRESSED_BYTE_COUNT); // Ensure the PublicKey is always 33 bytes (i.e. when point is infinity).
        ByteUtil.setBytes(compressedBytes.unwrap(), encodedBytes, offset);

        return PublicKey.fromBytes(compressedBytes);
    }
}
