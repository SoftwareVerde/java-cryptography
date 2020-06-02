package com.softwareverde.security.util;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.security.hash.murmur.MurmurHashUtil;
import com.softwareverde.security.hash.ripemd160.MutableRipemd160Hash;
import com.softwareverde.security.hash.sha256.MutableSha256Hash;
import com.softwareverde.security.hash.sha256.Sha256Hash;
import com.softwareverde.security.hash.sha512.MutableSha512Hash;
import com.softwareverde.security.secp256k1.key.PrivateKey;
import org.bouncycastle.crypto.digests.RIPEMD160Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class HashUtil {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    protected HashUtil() { }

    public static byte[] md5(final byte[] data) {
        try {
            final MessageDigest messageDigest = java.security.MessageDigest.getInstance("MD5");
            return messageDigest.digest(data);
        }
        catch (final NoSuchAlgorithmException exception) {
            return null;
        }
    }

    public static ByteArray md5(final ByteArray data) {
        return MutableByteArray.wrap(HashUtil.md5(data.getBytes()));
    }

    public static byte[] sha1(final byte[] data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
            return messageDigest.digest(data);
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static ByteArray sha1(final ByteArray data) {
        return MutableByteArray.wrap(HashUtil.sha1(data.getBytes()));
    }

    /**
     * Uses Java's native implementation of SHA256.
     *  This implementation is faster than BouncyCastle's implementation,
     *  however, it has poor performance when parallelized across multiple
     *  threads since it has an internal lock.
     */
    public static byte[] sha256_jvm(final byte[] data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            return messageDigest.digest(data);
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }


    /**
     * Uses BouncyCastle's implementation of SHA256.
     *  This implementation is slower than Java's native implementation,
     *  however, it may be parallelized whereas Java's native implementation
     *  has an internal lock.
     */
    public static byte[] sha256_bc(final byte[] data) {
        final SHA256Digest messageDigest = new SHA256Digest();
        messageDigest.update(data, 0, data.length);

        final byte[] hashedBytes = new byte[Sha256Hash.BYTE_COUNT];
        messageDigest.doFinal(hashedBytes, 0);
        return hashedBytes;
    }

    public static byte[] sha256(final byte[] data) {
        return HashUtil.sha256_jvm(data);
    }

    public static MutableSha256Hash sha256(final ByteArray data) {
        return MutableSha256Hash.wrap(HashUtil.sha256(data.getBytes()));
    }

    public static byte[] doubleSha256(final byte[] data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            final byte[] intermediarySha256Bytes = messageDigest.digest(data);
            return messageDigest.digest(intermediarySha256Bytes);
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static MutableSha256Hash doubleSha256(final ByteArray data) {
        return MutableSha256Hash.wrap(HashUtil.doubleSha256(data.getBytes()));
    }

    public static ByteArray sha256Hmac(final ByteArray data, final PrivateKey privateKey) {
        final HMac hmac = new HMac(new SHA256Digest());

        hmac.init(new KeyParameter(privateKey.getBytes()));
        final MutableByteArray hmacResult = new MutableByteArray(hmac.getMacSize());

        hmac.update(data.getBytes(), 0, data.getByteCount());
        hmac.doFinal(hmacResult.unwrap(), 0);

        return hmacResult;
    }

    public static MutableSha512Hash sha512(final ByteArray data) {
        try {
            final MessageDigest messageDigest = MessageDigest.getInstance("SHA-512");
            return MutableSha512Hash.wrap(messageDigest.digest(data.getBytes()));
        }
        catch (final NoSuchAlgorithmException exception) {
            throw new RuntimeException(exception);
        }
    }

    public static byte[] ripemd160(final byte[] data) {
        final RIPEMD160Digest ripemd160Digest = new RIPEMD160Digest();
        ripemd160Digest.update(data, 0, data.length);
        final byte[] output = new byte[ripemd160Digest.getDigestSize()];
        ripemd160Digest.doFinal(output, 0);
        return output;
    }

    public static MutableRipemd160Hash ripemd160(final ByteArray data) {
        return MutableRipemd160Hash.wrap(HashUtil.ripemd160(data.getBytes()));
    }

    public static Long murmurHash(final Long nonce, final Integer functionIdentifier, final ByteArray bytes) {
        int h1 = (int) ((functionIdentifier * 0xFBA4C795L) + nonce); // TODO: Ensure other clients handle integer overflow the same way when initializing h1...
        return MurmurHashUtil.hashVersion3x86_32(h1, bytes);
    }
}
