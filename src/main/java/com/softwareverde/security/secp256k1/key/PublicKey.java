package com.softwareverde.security.secp256k1.key;

import com.softwareverde.security.secp256k1.Secp256k1;
import com.softwareverde.constable.Const;
import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.ImmutableByteArray;

public class PublicKey extends ImmutableByteArray implements Const {
    public static PublicKey fromBytes(final ByteArray bytes) {
        if (bytes == null) { return null; }

        return new PublicKey(bytes);
    }

    protected Boolean _isCompressed() {
        if (_bytes.length != 33) { return false; }

        final byte firstByte = _bytes[0];
        return ( (firstByte == (byte) 0x02) || (firstByte == (byte) 0x03) );
    }

    protected Boolean _isDecompressed() {
        if (_bytes.length != 65) { return false; }

        final byte firstByte = _bytes[0];
        return (firstByte == (byte) 0x04);
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
        if (decompressedBytes == null) { return this; }

        decompressedBytes[0] = (byte) 0x04;
        return new PublicKey(decompressedBytes);
    }

    public PublicKey compress() {
        if (_bytes.length == 0) { return this; } // NOP
        if (_isCompressed()) { return this; }

        final Integer coordinateByteCount = ((_bytes.length - 1) / 2);

        final Integer prefixByteCount = 1;
        // final byte prefix = _bytes[0];
        final byte[] publicKeyPointX = new byte[coordinateByteCount];
        final byte[] publicKeyPointY = new byte[coordinateByteCount];
        {
            for (int i = 0; i < coordinateByteCount; ++i) {
                publicKeyPointX[i] = _bytes[prefixByteCount + i];
                publicKeyPointY[i] = _bytes[prefixByteCount + coordinateByteCount + i];
            }
        }
        final Boolean yCoordinateIsEven = ((publicKeyPointY[coordinateByteCount - 1] & 0xFF) % 2 == 0);
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
