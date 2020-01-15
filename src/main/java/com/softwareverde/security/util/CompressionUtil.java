package com.softwareverde.security.util;

import com.softwareverde.util.Base64Util;
import com.softwareverde.util.IoUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;
import java.util.zip.InflaterInputStream;

public class CompressionUtil {

    public static String toCompressedBase64(final byte[] data) throws IOException {
        final Deflater deflater = new Deflater(Deflater.DEFAULT_COMPRESSION);

        final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        final DeflaterOutputStream deflaterOutputStream = new DeflaterOutputStream(byteArrayOutputStream, deflater);
        deflaterOutputStream.write(data);
        deflaterOutputStream.close();

        final String base64 = Base64Util.toBase64String(byteArrayOutputStream.toByteArray());
        return base64;
    }

    public static byte[] fromCompressedBase64(final String data) {
        final byte[] compressedData = Base64Util.base64StringToByteArray(data);

        final ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(compressedData);
        final InflaterInputStream inflaterInputStream = new InflaterInputStream(byteArrayInputStream);
        final byte[] decompressedData = IoUtil.readStream(inflaterInputStream);

        return decompressedData;
    }
}
