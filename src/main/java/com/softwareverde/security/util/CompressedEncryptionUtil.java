package com.softwareverde.security.util;

import com.softwareverde.logging.Logger;
import com.softwareverde.logging.LoggerInstance;
import com.softwareverde.security.aes.AesKey;
import com.softwareverde.util.IoUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;

/**
 * <p>Provides methods for AES encrypting and decrypting data with optional compression using the INFLATE and DEFLATE algorithms.</p>
 */
public class CompressedEncryptionUtil {
    private static final LoggerInstance _logger = Logger.getInstance(CompressedEncryptionUtil.class);

    /**
     * Do not instantiate.
     */
    private CompressedEncryptionUtil() {}

    public static byte[] encryptDocument(final byte[] document, final AesKey aesKey) throws IOException {
        return encryptDocument(document, aesKey, Deflater.DEFAULT_COMPRESSION);
    }

    public static byte[] encryptDocument(final byte[] document, final AesKey aesKey, final int compressionLevel) throws IOException {
        final byte[] compressedDocument = _compressDocument(document, compressionLevel);
        final byte[] encryptedDocument = aesKey.encrypt(compressedDocument);
        return encryptedDocument;
    }

    protected static byte[] _compressDocument(final byte[] document, final int compressionLevel) throws IOException {
        final Deflater deflater = new Deflater(compressionLevel);

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        deflaterOutputStream.write(document);
        deflaterOutputStream.close();

        return byteArrayOutputStream.toByteArray();
    }

    public static byte[] decryptDocument(final byte[] encryptedDocument, final AesKey encryptionKey) {
        return decryptDocument(encryptedDocument, encryptionKey, null);
    }

    public static byte[] decryptDocument(final byte[] encryptedDocument, final AesKey encryptionKey, final Long expectedFileSize) {
        final byte[] decryptedDocument = encryptionKey.decrypt(encryptedDocument);
        final byte[] decompressedDocument;
        if (expectedFileSize == null) {
            decompressedDocument = _decompressDocument(decryptedDocument);
        }
        else {
            decompressedDocument = _decompressDocument(decryptedDocument, expectedFileSize);
        }
        return decompressedDocument;
    }

    protected static byte[] _decompressDocument(final byte[] document) {
        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(document);
        final InflaterInputStream inflaterInputStream = new InflaterInputStream(byteArrayInputStream);
        final byte[] decompressedDocument = IoUtil.readStream(inflaterInputStream);

        return decompressedDocument;
    }

    protected static byte[] _decompressDocument(final byte[] document, final long expectedFileSize) {
        if (expectedFileSize > Integer.MAX_VALUE) {
            throw new RuntimeException("Expected file size of " + expectedFileSize + " is not supported with a single byte array");
        }
        final int expectedInflationSize = (int) expectedFileSize;
        try {
            final byte[] decompressedDocument = new byte[expectedInflationSize];
            final Inflater inflater = new Inflater();
            inflater.setInput(document);
            int startIndex = 0;
            int bytesRead;
            while ((bytesRead = inflater.inflate(decompressedDocument, startIndex, expectedInflationSize - startIndex)) != 0) {
                startIndex += bytesRead;
            }
            return decompressedDocument;
        }
        catch (final Exception exception) {
            throw new RuntimeException("Unable to decompress document", exception);
        }
    }
}
