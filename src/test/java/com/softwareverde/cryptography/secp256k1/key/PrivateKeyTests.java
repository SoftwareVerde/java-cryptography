package com.softwareverde.cryptography.secp256k1.key;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.util.HexUtil;
import org.junit.Assert;
import org.junit.Test;

public class PrivateKeyTests {
    @Test
    public void should_not_create_private_key_with_all_zero_bytes() {
        // Setup
        final ByteArray privateKeyBytes = MutableByteArray.wrap(HexUtil.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000000"));

        // Action
        final PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);

        // Assert
        Assert.assertNull(privateKey);
    }

    @Test
    public void should_create_private_key_with_min_value() {
        // Setup
        final ByteArray privateKeyBytes = MutableByteArray.wrap(HexUtil.hexStringToByteArray("0000000000000000000000000000000000000000000000000000000000000001"));

        // Action
        final PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);

        // Assert
        Assert.assertNotNull(privateKey);
    }

    @Test
    public void should_create_private_key_with_max_valid_value() {
        // Setup
        final ByteArray privateKeyBytes = MutableByteArray.wrap(HexUtil.hexStringToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"));

        // Action
        final PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);

        // Assert
        Assert.assertNotNull(privateKey);
    }

    @Test
    public void should_not_create_private_key_with_one_over_max_valid_value() {
        // Setup
        final ByteArray privateKeyBytes = MutableByteArray.wrap(HexUtil.hexStringToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"));

        // Action
        final PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);

        // Assert
        Assert.assertNull(privateKey);
    }

    @Test
    public void should_not_create_private_key_with_all_F_bytes() {
        // Setup
        final ByteArray privateKeyBytes = MutableByteArray.wrap(HexUtil.hexStringToByteArray("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"));

        // Action
        final PrivateKey privateKey = PrivateKey.fromBytes(privateKeyBytes);

        // Assert
        Assert.assertNull(privateKey);
    }
}
