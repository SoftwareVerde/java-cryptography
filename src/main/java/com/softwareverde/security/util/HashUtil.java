package com.softwareverde.security.util;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.security.murmur.MurmurHashUtil;
import com.softwareverde.security.ripemd160.MutableRipemd160Hash;
import com.softwareverde.security.ripemd160.Ripemd160Hash;
import com.softwareverde.security.sha256.MutableSha256Hash;
import com.softwareverde.security.sha256.Sha256Hash;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil extends com.softwareverde.util.HashUtil {
    protected HashUtil() { }

    public static byte[] sha1(final byte[] data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            return messageDigest.digest(data);
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static byte[] sha256(final byte[] data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return messageDigest.digest(data);
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static Sha256Hash sha256(final ByteArray data) {
        return MutableSha256Hash.wrap(HashUtil.sha256(data.getBytes()));
    }

    public static byte[] ripemd160(final byte[] data) {
        final RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        ripemd160Digest.update(data, 0, data.length);
        final byte[] output = new byte[ripemd160Digest.getDigestSize()];
        ripemd160Digest.doFinal(output, 0);
        return output;
    }

    public static Ripemd160Hash ripemd160(final ByteArray data) {
        return MutableRipemd160Hash.wrap(HashUtil.ripemd160(data.getBytes()));
    }

    public static Long murmurHash(final Long nonce, final Integer functionIdentifier, final ByteArray bytes) {
        int h1 = (int) ((functionIdentifier * 0xFBA4C795L) + nonce); // TODO: Ensure other clients handle integer overflow the same way when initializing h1...
        return MurmurHashUtil.hashVersion3x86_32(h1, bytes);
    }
}
