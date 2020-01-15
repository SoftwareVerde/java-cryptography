package com.softwareverde.security.util;

import java.util.ArrayList;
import java.util.List;

public class LengthOnlyPasswordValidator extends PasswordValidator {
    private final int _requiredLength;

    public LengthOnlyPasswordValidator() {
        this(12);
    }

    public LengthOnlyPasswordValidator(final int requiredLength) {
        _requiredLength = requiredLength;
    }

    @Override
    public List<String> validatePassword(final CharSequence password) {
        final List<String> errors = new ArrayList<>(1);

        if (password.length() < _requiredLength) {
            errors.add("Password must be contain least " + _requiredLength + " characters.");
        }

        return errors;
    }
}
