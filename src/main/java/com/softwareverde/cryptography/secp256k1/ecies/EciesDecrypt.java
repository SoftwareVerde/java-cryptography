package com.softwareverde.cryptography.secp256k1.ecies;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.secp256k1.key.PrivateKey;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.cryptography.util.HashUtil;
import com.softwareverde.logging.Logger;
import com.softwareverde.util.Util;
import com.softwareverde.util.bytearray.ByteArrayBuilder;

public class EciesDecrypt {
    protected final PrivateKey _localPrivateKey;
    protected final PublicKey _senderPublicKey;
    protected Boolean _requireSenderPublicKey;

    /**
     * <p>Prepare to decrypt a message encrypted using the public key corresponding to localPrivateKey.</p>
     *
     * <p>This will require that the sending public key is included in the ciphertext, e.g. if
     * an ephemeral sending keypair was used.</p>
     * @param localPrivateKey
     */
    public EciesDecrypt(final PrivateKey localPrivateKey) {
        this(localPrivateKey, null, true);
    }

    /**
     * <p>Prepare to decrypt a message encrypted using the public key corresponding to localPrivateKey, assuming
     * it was sent using senderPublicKey.</p>
     *
     * <p>If a sender public key is included in the ciphertext, it will be ignored.</p>
     * @param localPrivateKey
     * @param senderPublicKey
     */
    public EciesDecrypt(final PrivateKey localPrivateKey, final PublicKey senderPublicKey) {
        this(localPrivateKey, senderPublicKey, false);
    }

    /**
     * <p>Prepare to decrypt a message encrypted using the public key corresponding to localPrivateKey, assuming
     * it was sent using senderPublicKey.</p>
     *
     * <p>The sender key will be required to be in the ciphertext and match the provided senderPublicKey if and only if
     * requireSenderPublicKey is true.  Otherwise, the senderPublicKey will be used and the public key in the ciphertext will be ignored.</p>
     * @param localPrivateKey
     * @param senderPublicKey
     * @param requireSenderPublicKey
     */
    public EciesDecrypt(final PrivateKey localPrivateKey, final PublicKey senderPublicKey, final Boolean requireSenderPublicKey) {
        _localPrivateKey = localPrivateKey;
        _senderPublicKey = senderPublicKey;
        _requireSenderPublicKey = requireSenderPublicKey;
    }

    public ByteArray decrypt(final ByteArray data) {
        final int publicKeyByteCount;
        final PublicKey sendersPublicKey;
        if (_requireSenderPublicKey) {
            final ByteArray publicKeyBytes;
            if (Util.areEqual(PublicKey.UNCOMPRESSED_FIRST_BYTE, data.getByte(0))) {
                publicKeyBytes = MutableByteArray.wrap(data.getBytes(0, PublicKey.UNCOMPRESSED_BYTE_COUNT));
                publicKeyByteCount = PublicKey.UNCOMPRESSED_BYTE_COUNT;
            }
            else {
                publicKeyBytes = MutableByteArray.wrap(data.getBytes(0, PublicKey.COMPRESSED_BYTE_COUNT));
                publicKeyByteCount = PublicKey.COMPRESSED_BYTE_COUNT;
            }
            sendersPublicKey = PublicKey.fromBytes(publicKeyBytes).compress();
            if ((sendersPublicKey == null) || (! sendersPublicKey.isValid())) {
                Logger.debug("Unable to obtain sender public key.");
                return null;
            }

            if ((_senderPublicKey != null) && (! Util.areEqual(_senderPublicKey.compress(), sendersPublicKey)) ) {
                Logger.debug("Expected sender key did not match sender key in ciphertext.");
                return null;
            }
        }
        else {
            publicKeyByteCount = 0;
            sendersPublicKey = _senderPublicKey;
        }

        final int hmacByteCount = 32;

        final ByteArray c;
        {
            final int cByteCount = (data.getByteCount() - publicKeyByteCount - hmacByteCount);
            c = MutableByteArray.wrap(data.getBytes(publicKeyByteCount, cByteCount));
        }

        final ByteArray d;
        {
            final int dOffset = (data.getByteCount() - hmacByteCount);
            d = EciesUtil.substring(data, dOffset);
        }

        final ByteArrayBuilder hmacPreImage = new ByteArrayBuilder();
        {
            final ByteArray initializationVector = MutableByteArray.wrap(c.getBytes(0, EciesUtil.Aes.INITIALIZATION_VECTOR_BYTE_COUNT));
            final ByteArray ct = EciesUtil.substring(c, EciesUtil.Aes.INITIALIZATION_VECTOR_BYTE_COUNT);

            hmacPreImage.appendBytes(initializationVector);
            if (_requireSenderPublicKey) {
                hmacPreImage.appendBytes(sendersPublicKey);
            }
            hmacPreImage.appendBytes(ct);
        }

        final ByteArray d2;
        {
            final PrivateKey kM = EciesUtil.getLastK(sendersPublicKey, _localPrivateKey);
            d2 = HashUtil.sha256Hmac(MutableByteArray.wrap(hmacPreImage.build()), kM);
        }

        final boolean checksumMatches = Util.areEqual(d, d2);
        if (! checksumMatches) {
            Logger.debug("Invalid MAC for ciphertext");
            return null;
        }

        final PrivateKey kE = EciesUtil.getFirstK(sendersPublicKey, _localPrivateKey);
        return EciesUtil.Aes.decrypt(c, kE);
    }
}
