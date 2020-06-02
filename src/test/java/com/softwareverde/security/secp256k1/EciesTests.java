package com.softwareverde.security.secp256k1;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.security.secp256k1.key.PrivateKey;
import com.softwareverde.security.secp256k1.key.PublicKey;
import com.softwareverde.util.StringUtil;
import org.junit.Assert;
import org.junit.Test;

public class EciesTests {
    @Test
    public void should_encrypt_and_decrypt_data() {
        // Setup
        final PrivateKey sendersPrivateKey = PrivateKey.createNewKey();
        final PublicKey sendersPublicKey = sendersPrivateKey.getPublicKey();

        final PrivateKey recipientPrivateKey = PrivateKey.createNewKey();
        final PublicKey recipientPublicKey = recipientPrivateKey.getPublicKey();

        final String message = "Mary had a little lamb.";
        final ByteArray payload = ByteArray.wrap(StringUtil.stringToBytes(message));

        final Ecies ecies = new Ecies(sendersPrivateKey, recipientPublicKey);
        final Ecies recipientEcies = new Ecies(recipientPrivateKey, sendersPublicKey);

        // Action
        final ByteArray encryptedPayload = ecies.encrypt(payload);
        final ByteArray decryptedPayload = recipientEcies.decrypt(encryptedPayload);

        // Assert
        Assert.assertEquals(payload, decryptedPayload);
    }

    @Test
    public void bitcore_test() {
        // Setup
        final PrivateKey alicePrivateKey = PrivateKey.fromHexString("77E06ABC52BF065CB5164C5DECA839D0276911991A2730BE4D8D0A0307DE7CEB");
        final PrivateKey bobPrivateKey = PrivateKey.fromHexString("2B57C7C5E408CE927EEF5E2EFB49CFDADDE77961D342DAA72284BB3D6590862D");
        Assert.assertNotNull(alicePrivateKey);
        Assert.assertNotNull(bobPrivateKey);

        final ByteArray message = ByteArray.wrap(StringUtil.stringToBytes("attack at dawn"));
        // 0339E504D6492B082DA96E11E8F039796B06CD4855C101E2492A6F10F3E056A9E712C732611C6917AB5C57A1926973BC44A1586E94A783F81D05CE72518D9B0A80E2E13C7FF7D1306583F9CC7A48DEF5B37FBF2D5F294F128472A6E9C78DEDE5F5
        final ByteArray expectedEncryptedValue = ByteArray.fromHexString("12C732611C6917AB5C57A1926973BC44A1586E94A783F81D05CE72518D9B0A80E2E13C7FF7D1306583F9CC7A48DEF5B37FBF2D5F294F128472A6E9C78DEDE5F5");

        final Ecies senderEcies = new Ecies(alicePrivateKey, bobPrivateKey.getPublicKey().compress());
        senderEcies.setIncludePublicKey(false);

        final Ecies receiverEcies = new Ecies(bobPrivateKey, alicePrivateKey.getPublicKey());
        receiverEcies.setIncludePublicKey(false);

        // Action
        final ByteArray encryptedValue = senderEcies.encrypt(message);
        final ByteArray decryptedValue = receiverEcies.decrypt(encryptedValue);

        // Assert
        Assert.assertNotNull(encryptedValue);
        Assert.assertEquals(expectedEncryptedValue, encryptedValue);

        Assert.assertNotNull(decryptedValue);
        Assert.assertEquals(message, decryptedValue);

    }
}
