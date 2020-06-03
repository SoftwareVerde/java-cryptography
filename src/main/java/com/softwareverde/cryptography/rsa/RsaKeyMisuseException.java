package com.softwareverde.cryptography.rsa;

public class RsaKeyMisuseException extends RuntimeException {
    public RsaKeyMisuseException() {
        super();
    }

    public RsaKeyMisuseException(final String message) {
        super(message);
    }
}
