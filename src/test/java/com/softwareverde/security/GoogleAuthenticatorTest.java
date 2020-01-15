package com.softwareverde.security;

import org.junit.Assert;
import org.junit.Test;

public class GoogleAuthenticatorTest {

    @Test
    public void should_allow_only_current_code_by_default() {
        // Setup
        final String secret = "zxsdf7quxv5ysnhneznpwu2hxclrxmuz"; // URI: otpauth://totp/Test%20Company:user@test.com?secret=zxsdf7quxv5ysnhneznpwu2hxclrxmuz&issuer=Test%20Company
        final int code1 = 987305;
        final long code1Timestamp = 1565277447982L;
        final int code2 = 178029;
        final long code2Timestamp = 1565277462918L;

        // Action
        final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator();

        // Test
        Assert.assertTrue(googleAuthenticator.checkCode(secret, code1, code1Timestamp));
        Assert.assertFalse(googleAuthenticator.checkCode(secret, code2, code1Timestamp));
        Assert.assertTrue(googleAuthenticator.checkCode(secret, code2, code2Timestamp));
    }

    @Test
    public void should_allow_prior_code_with_increased_window_size() {
        // Setup
        final String secret = "zxsdf7quxv5ysnhneznpwu2hxclrxmuz";
        final int code1 = 987305;
        final long code1Timestamp = 1565277447982L;
        final int code2 = 178029;
        final long code2Timestamp = 1565277462918L;
        final int laterCode = 463868;
        final long laterCodeTimestamp = 1565278415635L;

        // Action
        final GoogleAuthenticator googleAuthenticator = new GoogleAuthenticator(1);

        // Test
        Assert.assertTrue(googleAuthenticator.checkCode(secret, code1, code1Timestamp));
        Assert.assertTrue(googleAuthenticator.checkCode(secret, code2, code1Timestamp));
        Assert.assertTrue(googleAuthenticator.checkCode(secret, code2, code2Timestamp));
        Assert.assertFalse(googleAuthenticator.checkCode(secret, laterCode, code1Timestamp));
        Assert.assertFalse(googleAuthenticator.checkCode(secret, laterCode, code2Timestamp));
        Assert.assertTrue(googleAuthenticator.checkCode(secret, laterCode, laterCodeTimestamp));
        Assert.assertFalse(googleAuthenticator.checkCode(secret, code1, laterCodeTimestamp));
        Assert.assertFalse(googleAuthenticator.checkCode(secret, code2, laterCodeTimestamp));

    }
}
