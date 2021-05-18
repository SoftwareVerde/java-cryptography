package com.softwareverde.cryptography.util;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.hash.sha256.Sha256Hash;
import com.softwareverde.cryptography.hash.sha512.Sha512Hash;
import com.softwareverde.util.ByteUtil;
import com.softwareverde.util.StringUtil;
import com.softwareverde.util.timer.NanoTimer;
import org.junit.Assert;
import org.junit.Test;

public class HashUtilTests {
    @Test
    public void should_hash_sha256() {
        // Setup
        final byte[] preImage = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        final ByteArray expectedBytes = MutableByteArray.wrap(HashUtil.sha256(HashUtil.sha256(preImage)));

        // Action
        final Sha256Hash doubleSha256Hash = HashUtil.doubleSha256(MutableByteArray.wrap(preImage));

        // Assert
        Assert.assertEquals(expectedBytes, doubleSha256Hash);
    }

    @Test
    public void should_hash_sha256_string() {
        // Setup
        final byte[] preImage = StringUtil.stringToBytes("Mary had a little lamb.");
        final ByteArray expectedBytes = ByteArray.fromHexString("D2FC16A1F51A653AA01964EF9C923336E10653FEC195F493458B3B21890E1B97");

        // Action
        final Sha256Hash sha256Hash = HashUtil.sha256(MutableByteArray.wrap(preImage));

        // Assert
        Assert.assertEquals(expectedBytes, sha256Hash);
    }

    static class HasherThread extends Thread {
        protected final NanoTimer _timer;
        protected byte[] _preImage;

        public static HasherThread newInstance(final byte[] bytes, final boolean useBc) {
            final NanoTimer timer = new NanoTimer();
            final byte[] preImage = ByteUtil.copyBytes(bytes);
            final Runnable runnable = new Runnable() {
                @Override
                public void run() {
                    byte[] bytes = preImage;
                    timer.start();
                    for (int i = 0; i < 10000000; ++i) {
                        if (useBc) {
                            bytes = HashUtil.sha256_bc(bytes);
                        }
                        else {
                            bytes = HashUtil.sha256_jvm(bytes);
                        }
                    }
                    timer.stop();
                }
            };

            return new HasherThread(preImage, runnable, timer);
        }

        protected HasherThread(final byte[] preImage, final Runnable runnable, final NanoTimer timer) {
            super(runnable);
            _timer = timer;
            _preImage = preImage;
        }

        public Long getMillisecondsElapsed() {
            return _timer.getMillisecondsElapsed().longValue();
        }
    }

    @Test
    public void time_sha256_jvm_vs_bc() throws Exception {
        byte[] preImage = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };

        final NanoTimer jvmNanoTimer = new NanoTimer();
        jvmNanoTimer.start();
        for (int i = 0; i < 10000000; ++i) {
            preImage = HashUtil.sha256_jvm(preImage);
        }
        jvmNanoTimer.stop();

        final NanoTimer bcNanoTimer = new NanoTimer();
        bcNanoTimer.start();
        for (int i = 0; i < 10000000; ++i) {
            preImage = HashUtil.sha256_bc(preImage);
        }
        bcNanoTimer.stop();

        System.out.println("JVM: " + jvmNanoTimer.getMillisecondsElapsed());
        System.out.println(" BC: " + bcNanoTimer.getMillisecondsElapsed());

        final HasherThread[] threads = new HasherThread[2];
        for (int i = 0; i < threads.length; ++i) {
            threads[i] = HasherThread.newInstance(preImage, true);
        }

        final NanoTimer threadedBcTimer = new NanoTimer();
        threadedBcTimer.start();
        for (int i = 0; i < threads.length; ++i) {
            threads[i].start();
        }
        for (int i = 0; i < threads.length; ++i) {
            threads[i].join();
        }
        threadedBcTimer.stop();

        for (int i = 0; i < threads.length; ++i) {
            threads[i] = HasherThread.newInstance(preImage, false);
        }

        final NanoTimer threadedJvmTimer = new NanoTimer();
        threadedJvmTimer.start();
        for (int i = 0; i < threads.length; ++i) {
            threads[i].start();
        }
        for (int i = 0; i < threads.length; ++i) {
            threads[i].join();
        }
        threadedJvmTimer.stop();

        System.out.println("Thread JVM: " + threadedJvmTimer.getMillisecondsElapsed());
        System.out.println("Thread  BC: " + threadedBcTimer.getMillisecondsElapsed());
    }

    @Test
    public void should_hash_sha256_with_threaded_implementation_when_in_use_by_other_thread() {
        // Setup
        final byte[] preImage = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        final ByteArray expectedBytes = MutableByteArray.wrap(HashUtil.sha256(HashUtil.sha256(preImage)));

        // Action
        final Sha256Hash doubleSha256Hash = HashUtil.doubleSha256(MutableByteArray.wrap(preImage));

        // Assert
        Assert.assertEquals(expectedBytes, doubleSha256Hash);
    }

    @Test
    public void should_hash_sha512() {
        // Setup
        final byte[] preImage = new byte[]{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09 };
        final ByteArray expectedBytes = ByteArray.fromHexString("0F89EE1FCB7B0A4F7809D1267A029719004C5A5E5EC323A7C3523A20974F9A3F202F56FADBA4CD9E8D654AB9F2E96DC5C795EA176FA20EDE8D854C342F903533");

        // Action
        final Sha512Hash sha512Hash = HashUtil.sha512(MutableByteArray.wrap(preImage));
        System.out.println(sha512Hash);

        // Assert
        Assert.assertEquals(expectedBytes, sha512Hash);
    }

    @Test
    public void should_hash_sha512_string() {
        // Setup
        final byte[] preImage = StringUtil.stringToBytes("Mary had a little lamb.");
        final ByteArray expectedBytes = ByteArray.fromHexString("35154F15409907FD431E20ABAD63EFB35F7992C71A847E70DB0AA95D13D51279D489C6A4BFBFA57F03E114BAC5808A8AFF1C666818C5FAF8225CE4C27D22BFC3");

        // Action
        final Sha512Hash sha512Hash = HashUtil.sha512(MutableByteArray.wrap(preImage));
        System.out.println(sha512Hash);

        // Assert
        Assert.assertEquals(expectedBytes, sha512Hash);
    }
}