package com.softwareverde.cryptography.secp256k1;

import com.softwareverde.constable.bytearray.ByteArray;
import com.softwareverde.constable.bytearray.MutableByteArray;
import com.softwareverde.cryptography.hash.sha256.Sha256Hash;
import com.softwareverde.cryptography.secp256k1.key.PublicKey;
import com.softwareverde.util.Util;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

public class EcMultisetTests {
    // Test Vectors obtained from: https://github.com/tomasvdw/bips/blob/master/ecmh.mediawiki#test-vectors

    public static final ByteArray D1_BYTES = ByteArray.fromHexString("982051FD1E4BA744BBBE680E1FEE14677BA1A3C3540BF7B1CDB606E857233E0E00000000010000000100F2052A0100000043410496B538E853519C726A2C91E61EC11600AE1390813A627C66FB8BE7947BE63C52DA7589379515D4E0A604F8141781E62294721166BF621E73A82CBF2342C858EEAC");
    public static final ByteArray D2_BYTES = ByteArray.fromHexString("D5FDCC541E25DE1C7A5ADDEDF24858B8BB665C9F36EF744EE42C316022C90F9B00000000020000000100F2052A010000004341047211A824F55B505228E4C3D5194C1FCFAA15A456ABDF37F9B9D97A4040AFC073DEE6C89064984F03385237D92167C13E236446B417AB79A0FCAE412AE3316B77AC");
    public static final ByteArray D3_BYTES = ByteArray.fromHexString("44F672226090D85DB9A9F2FBFE5F0F9609B387AF7BE5B7FBB7A1767C831C9E9900000000030000000100F2052A0100000043410494B9D3E76C5B1629ECF97FFF95D7A4BBDAC87CC26099ADA28066C6FF1EB9191223CD897194A08D0C2726C5747F1DB49E8CF90E75DC3E3550AE9B30086F3CD5AAAC");

    @Before
    public void before() throws Exception { }

    @After
    public void after() throws Exception { }

    @Test
    public void should_be_an_empty_hash_if_empty() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.EMPTY_HASH;
        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        final Sha256Hash value = ecMultiset.getHash();
        final PublicKey publicKey = ecMultiset.getPublicKey();

        // Assert
        Assert.assertEquals(expectedValue, value);
        Assert.assertTrue(Util.areEqual(new MutableByteArray(PublicKey.COMPRESSED_BYTE_COUNT), publicKey));
    }

    @Test
    public void should_calculate_multiset_hash_1() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("F883195933A687170C34FA1ADEC66FE2861889279FB12C03A3FB0CA68AD87893");
        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D1_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_multiset_hash_2() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("EF85D123A15DA95D8AFF92623AD1E1C9FCDA3BAA801BD40BC567A83A6FDCF3E2");
        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D2_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_multiset_hash_3() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("CFADF40FC017FAFF5E04CCC0A2FAE0FD616E4226DD7C03B1334A7A610468EDFF");
        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D3_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_merged_multiset_hash_of_d1_and_d2() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF");

        final EcMultiset ecMultiset = new EcMultiset();
        ecMultiset.addItem(D1_BYTES);

        final EcMultiset d2EcMultiset = new EcMultiset();
        d2EcMultiset.addItem(D2_BYTES);

        // Action
        ecMultiset.add(d2EcMultiset);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_multiset_hash_of_d1_and_d2() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF");

        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D1_BYTES);
        ecMultiset.addItem(D2_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_merged_multiset_hash_of_d1_d2_and_d3() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2");

        final EcMultiset ecMultiset = new EcMultiset();
        ecMultiset.addItem(D1_BYTES);

        final EcMultiset d2EcMultiset = new EcMultiset();
        d2EcMultiset.addItem(D2_BYTES);

        final EcMultiset d3EcMultiset = new EcMultiset();
        d3EcMultiset.addItem(D3_BYTES);

        // Action
        ecMultiset.add(d2EcMultiset);
        ecMultiset.add(d3EcMultiset);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_multiset_hash_of_d1_d2_and_d3() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2");

        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D1_BYTES);
        ecMultiset.addItem(D2_BYTES);
        ecMultiset.addItem(D3_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_multiset_hash_of_d1_d2_after_adding_and_removing_d3() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("FABAFD38D07370982A34547DAF5B57B8A4398696D6FD2294788ABDA07B1FAAAF");

        final EcMultiset ecMultiset = new EcMultiset();

        // Action
        ecMultiset.addItem(D1_BYTES);
        ecMultiset.addItem(D2_BYTES);
        ecMultiset.addItem(D3_BYTES);
        ecMultiset.removeItem(D3_BYTES);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_calculate_merged_multiset_hash_of_d1p_d2p_and_d3p() {
        // Setup
        final Sha256Hash expectedValue = Sha256Hash.fromHexString("1CBCCDA23D7CE8C5A8B008008E1738E6BF9CFFB1D5B86A92A4E62B5394A636E2");

        final PublicKey d1PublicKey;
        {
            final EcMultiset ecMultiset = new EcMultiset();
            ecMultiset.addItem(D1_BYTES);
            d1PublicKey = ecMultiset.getPublicKey();
        }

        final PublicKey d2PublicKey;
        {
            final EcMultiset d2EcMultiset = new EcMultiset();
            d2EcMultiset.addItem(D2_BYTES);
            d2PublicKey = d2EcMultiset.getPublicKey().compress();
        }

        final PublicKey d3PublicKey;
        {
            final EcMultiset d3EcMultiset = new EcMultiset();
            d3EcMultiset.addItem(D3_BYTES);
            d3PublicKey = d3EcMultiset.getPublicKey().decompress();
        }

        // Action
        final EcMultiset ecMultiset = new EcMultiset(d1PublicKey);
        ecMultiset.add(d2PublicKey);
        ecMultiset.add(d3PublicKey);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_noop_when_adding_two_empty_sets() {
        // Setup
        final EcMultiset ecMultiset = new EcMultiset();
        final EcMultiset emptyEcMultiset = new EcMultiset();
        final Sha256Hash expectedValue = Sha256Hash.EMPTY_HASH;

        // Action
        ecMultiset.add(emptyEcMultiset);

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }

    @Test
    public void should_noop_when_adding_empty_pk() {
        // Setup
        final EcMultiset ecMultiset = new EcMultiset();
        final EcMultiset emptyEcMultiset = new EcMultiset();
        final Sha256Hash expectedValue = Sha256Hash.EMPTY_HASH;

        // Action
        ecMultiset.add(emptyEcMultiset.getPublicKey());

        // Assert
        final Sha256Hash value = ecMultiset.getHash();
        Assert.assertEquals(expectedValue, value);
    }
}
