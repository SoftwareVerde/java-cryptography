package com.softwareverde.cryptography.secp256k1.ecies;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.util.bytearray.ByteArrayBuilder;

public class EciesEncrypt {
    protected final PrivateKey _localPrivateKey;
    protected final PublicKey _recipientPublicKey;
    protected final Boolean _includeLocalPublicKey;

    /**
     * <p>Prepare to encrypt a message using the provided recipientPublicKey and an ephemeral sending key.</p>
     *
     * <p>This will force the ephemeral public key to be included in the ciphertext.</p>
     * @param recipientPublicKey
     */
    public EciesEncrypt(final PublicKey recipientPublicKey) {
        this(PrivateKey.createNewKey(), recipientPublicKey, true);
    }

    /**
     * <p>Prepare to encrypt a message with using the given localPrivateKey and the recipientPublicKey.</p>
     *
     * <p>This is a helper constructor for the use-case where the recipient is expected to know the sender,
     * so that public key corresponding to localPrivateKey will not be included with the ciphertext.</p>
     * @param localPrivateKey
     * @param recipientPublicKey
     */
    public EciesEncrypt(final PrivateKey localPrivateKey, final PublicKey recipientPublicKey) {
        this(localPrivateKey, recipientPublicKey, false);
    }

    /**
     * <p>Prepare to encrypt a message using the given localPrivateKey and the recipientPublicKey. The public key corresponding
     * to localPrivateKey will be included in the ciphertext if and only if includeLocalPublicKey is true.</p>
     * @param localPrivateKey
     * @param recipientPublicKey
     * @param includeLocalPublicKey
     */
    public EciesEncrypt(final PrivateKey localPrivateKey, final PublicKey recipientPublicKey, final Boolean includeLocalPublicKey) {
        _localPrivateKey = localPrivateKey;
        _recipientPublicKey = recipientPublicKey;
        _includeLocalPublicKey = includeLocalPublicKey;
    }

    public ByteArray encrypt(final ByteArray message) {
        return this.encrypt(message, null);
    }

    public ByteArray encrypt(final ByteArray message, final ByteArray nullableInitializationVector) {
        final PublicKey sendersPublicKey;
        {
            final PublicKey uncompressedPublicKey = _localPrivateKey.getPublicKey();
            sendersPublicKey = uncompressedPublicKey.compress();
        }

        final ByteArray initializationVector;
        {
            final ByteArray hmac = (nullableInitializationVector != null ? nullableInitializationVector : HashUtil.sha256Hmac(message, _localPrivateKey));
            initializationVector = MutableByteArray.wrap(hmac.getBytes(0, EciesUtil.Aes.INITIALIZATION_VECTOR_BYTE_COUNT));
        }

        final ByteArray c;
        {
            final PrivateKey kE = EciesUtil.getFirstK(_recipientPublicKey, _localPrivateKey);
            c = EciesUtil.Aes.encrypt(message, kE, initializationVector);
            if (c == null) { return null; }
        }

        final ByteArray d;
        {
            final ByteArray ct = EciesUtil.substring(c, EciesUtil.Aes.INITIALIZATION_VECTOR_BYTE_COUNT);
            final ByteArrayBuilder hmacPreImage = new ByteArrayBuilder();
            {
                hmacPreImage.appendBytes(initializationVector);
                if (_includeLocalPublicKey) {
                    hmacPreImage.appendBytes(sendersPublicKey);
                }
                hmacPreImage.appendBytes(ct);
            }

            final PrivateKey kM = EciesUtil.getLastK(_recipientPublicKey, _localPrivateKey);
            d = HashUtil.sha256Hmac(MutableByteArray.wrap(hmacPreImage.build()), kM);
        }

        final ByteArrayBuilder result = new ByteArrayBuilder();
        {
            if (_includeLocalPublicKey) {
                result.appendBytes(sendersPublicKey);
            }
            result.appendBytes(c);
            result.appendBytes(d);
        }

        return MutableByteArray.wrap(result.build());
    }
}
