package com.softwareverde.cryptography.secp256k1;

import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.secp256k1.signature.Signature;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.util.StringUtil;
import org.junit.Assert;
import org.junit.Test;

public class Secp256k1Tests {
    @Test
    public void should_create_and_verify_signature_bouncy_castle() {
        long elapsed = 0L;
        for (int i = 0; i < 128; ++i) {
            // Setup
            final PrivateKey privateKey = PrivateKey.createNewKey();
            final PublicKey publicKey = privateKey.getPublicKey();
            final byte[] message = StringUtil.stringToBytes("I am a little teapot." + i);

            // Action
            final Signature signature = Secp256k1.sign(privateKey, message);
            long start = System.currentTimeMillis();
            final Boolean signatureIsValid = Secp256k1._verifySignatureViaBouncyCastle(signature, publicKey, message);
            elapsed += System.currentTimeMillis() - start;

            // Assert
            Assert.assertTrue(signatureIsValid);
        }

        System.out.println("Verify via BC: "+ elapsed);
    }

    @Test
    public void should_create_and_verify_signature() {
        // Setup
        final PrivateKey privateKey = PrivateKey.createNewKey();
        final PublicKey publicKey = privateKey.getPublicKey();
        final byte[] message = HashUtil.sha256(StringUtil.stringToBytes("I am a little teapot."));

        // Action
        final Signature signature = Secp256k1.sign(privateKey, message);
        final Boolean signatureIsValid = Secp256k1.verifySignature(signature, publicKey, message);

        // Assert
        Assert.assertTrue(signatureIsValid);
    }
}
