package com.softwareverde.cryptography.argon2;

import com.softwareverde.util.HexUtil;
import org.bouncycastle.crypto.params.Argon2Parameters;
import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

public class Argon2Test {
    private static final int DEFAULT_OUTPUTLEN = 32;

    @Ignore("This test is time consuming and ultimately should be unnecessary for our purposes.  However, it could be useful if this class undergoes a lot of changes in the future.")
    @Test
    public void test_bouncy_castle_test_vectors() {
        int version = Argon2Parameters.ARGON2_VERSION_10;

        /* Multiple test cases for various input values */
        hashTest(version, 2, 16, 1, "password", "somesalt",
                "f6c4db4a54e2a370627aff3db6176b94a2a209a62c8e36152711802f7b30c694", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 20, 1, "password", "somesalt",
                "9690ec55d28d3ed32562f2e73ea62b02b018757643a2ae6e79528459de8106e9",
                DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 18, 1, "password", "somesalt",
                "3e689aaa3d28a77cf2bc72a51ac53166761751182f1ee292e3f677a7da4c2467",
                DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 1, "password", "somesalt",
                "fd4dd83d762c49bdeaf57c47bdcd0c2f1babf863fdeb490df63ede9975fccf06",
                DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 8, 2, "password", "somesalt",
                "b6c11560a6a9d61eac706b79a2f97d68b4463aa3ad87e00c07e2b01e90c564fb", DEFAULT_OUTPUTLEN);
        hashTest(version, 1, 16, 1, "password", "somesalt",
                "81630552b8f3b1f48cdb1992c4c678643d490b2b5eb4ff6c4b3438b5621724b2", DEFAULT_OUTPUTLEN);
        hashTest(version, 4, 16, 1, "password", "somesalt",
                "f212f01615e6eb5d74734dc3ef40ade2d51d052468d8c69440a3a1f2c1c2847b", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "e9c902074b6754531a3a0be519e5baf404b30ce69b3f01ac3bf21229960109a3", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "password", "diffsalt",
                "79a103b90fe8aef8570cb31fc8b22259778916f8336b7bdac3892569d4f1c497", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 16, 1, "password", "diffsalt",
                "1a097a5d1c80e579583f6e19c7e4763ccb7c522ca85b7d58143738e12ca39f8e6e42734c950ff2463675b97c37ba" +
                        "39feba4a9cd9cc5b4c798f2aaf70eb4bd044c8d148decb569870dbd923430b82a083f284beae777812cce18cdac68ee8ccef" +
                        "c6ec9789f30a6b5a034591f51af830f4",
                112);


        version = Argon2Parameters.ARGON2_VERSION_13;

        /* Multiple test cases for various input values */
        hashTest(version, 2, 16, 1, "password", "somesalt",
                "c1628832147d9720c5bd1cfd61367078729f6dfb6f8fea9ff98158e0d7816ed0",
                DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 20, 1, "password", "somesalt",
                "d1587aca0922c3b5d6a83edab31bee3c4ebaef342ed6127a55d19b2351ad1f41", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 18, 1, "password", "somesalt",
                "296dbae80b807cdceaad44ae741b506f14db0959267b183b118f9b24229bc7cb", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 1, "password", "somesalt",
                "89e9029f4637b295beb027056a7336c414fadd43f6b208645281cb214a56452f", DEFAULT_OUTPUTLEN);

        hashTest(version, 2, 8, 2, "password", "somesalt",
                "4ff5ce2769a1d7f4c8a491df09d41a9fbe90e5eb02155a13e4c01e20cd4eab61", DEFAULT_OUTPUTLEN);
        hashTest(version, 1, 16, 1, "password", "somesalt",
                "d168075c4d985e13ebeae560cf8b94c3b5d8a16c51916b6f4ac2da3ac11bbecf", DEFAULT_OUTPUTLEN);
        hashTest(version, 4, 16, 1, "password", "somesalt",
                "aaa953d58af3706ce3df1aefd4a64a84e31d7f54175231f1285259f88174ce5b", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "differentpassword", "somesalt",
                "14ae8da01afea8700c2358dcef7c5358d9021282bd88663a4562f59fb74d22ee", DEFAULT_OUTPUTLEN);
        hashTest(version, 2, 16, 1, "password", "diffsalt",
                "b0357cccfbef91f3860b0dba447b2348cbefecadaf990abfe9cc40726c521271", DEFAULT_OUTPUTLEN);
    }

    private void hashTest(int version, int iterations, int memory, int parallelism, String password, String salt, String passwordRef, int outputLength) {
        final Argon2 argon2 = new Argon2(Argon2Parameters.ARGON2_i, version, iterations, memory, parallelism, salt.getBytes(), outputLength);
        final byte[] result = argon2.generate(password.getBytes());

        Assert.assertEquals(outputLength, result.length);
        Assert.assertArrayEquals(HexUtil.hexStringToByteArray(passwordRef), result);
    }

    @Test
    public void test_generate_parameter_string() {
        // Setup
        final byte[] salt = HexUtil.hexStringToByteArray("EE1FF1331E63BB4F56A4D8C9A8B5E93A");
        final Argon2 argon2 = new Argon2(Argon2Parameters.ARGON2_id, Argon2Parameters.ARGON2_VERSION_13, 12, 16, 2, salt, 32);

        // Action
        final String parameterString = argon2.getParameterString();

        // Test
        Assert.assertEquals("Argon2$2$19$12$16$2$EE1FF1331E63BB4F56A4D8C9A8B5E93A$32", parameterString);
    }

    @Test
    public void test_parameter_string_constructor() {
        // Setup
        final byte[] salt = HexUtil.hexStringToByteArray("EE1FF1331E63BB4F56A4D8C9A8B5E93A");
        final String parameterString = "Argon2$2$19$16$24$2$EE1FF1331E63BB4F56A4D8C9A8B5E93A$32";

        // Action
        final Argon2 argon2 = new Argon2(parameterString);

        // Test
        Assert.assertEquals(Argon2Parameters.ARGON2_id, argon2.getArgon2Type());
        Assert.assertEquals(Argon2Parameters.ARGON2_VERSION_13, argon2.getArgon2Version());
        Assert.assertEquals(16, argon2.getIterations());
        Assert.assertEquals(24, argon2.getAllowedMemoryPowerOf2());
        Assert.assertEquals(2, argon2.getThreadCount());
        Assert.assertArrayEquals(salt, argon2.getSalt());
    }

    @Test
    public void test_generate_parameterized_hash() {
        final byte[] salt = HexUtil.hexStringToByteArray("EE1FF1331E63BB4F56A4D8C9A8B5E93A");
        final String password = "abcdefghijklmnopqrstuvwxyz";

        final Argon2 argon2 = new Argon2(Argon2Parameters.ARGON2_id, Argon2Parameters.ARGON2_VERSION_13, 12, 16, 2, salt, 32);
        final String parameterizedHash = argon2.generateParameterizedHash(password.getBytes());

        Assert.assertEquals("Argon2$2$19$12$16$2$EE1FF1331E63BB4F56A4D8C9A8B5E93A$32$987D66F8E2944C1637B4E650B4D84A8D0C45925901E7A069FC2A7CEC2EE2B798", parameterizedHash);
    }

    @Test
    public void test_should_produce_same_parameterized_hash_for_same_password() {
        final String parameterizedHash = "Argon2$2$19$12$16$2$2B328B3C634858A5820A34B742C2D957$32$2A2EF26D87C35B7630EB92C1D31B95953BBFBE7962C0F7F3F6023896D5C87E32";
        final String password = "abcdefghijklmnopqrstuvwxyz";

        final Argon2 argon2 = new Argon2(parameterizedHash);

        Assert.assertEquals(parameterizedHash, argon2.generateParameterizedHash(password.getBytes()));
    }

    @Test
    public void test_should_produce_different_parameterized_hash_for_different_password() {
        final String parameterizedHash = "Argon2$2$19$12$16$2$2B328B3C634858A5820A34B742C2D957$32$2A2EF26D87C35B7630EB92C1D31B95953BBFBE7962C0F7F3F6023896D5C87E32";
        final String badPassword = "abcdefghijklmnopqrstuvwxyy";

        final Argon2 argon2 = new Argon2(parameterizedHash);

        Assert.assertNotEquals(parameterizedHash, argon2.generateParameterizedHash(badPassword.getBytes()));
    }
}
