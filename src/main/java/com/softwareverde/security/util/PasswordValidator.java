package com.softwareverde.security.util;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class PasswordValidator {
    private Pattern _specialCharacterPattern;
    private Pattern _upperCasePattern;
    private Pattern _lowerCasePattern;
    private Pattern _digitPattern;

    public PasswordValidator() {
        _specialCharacterPattern = Pattern.compile("[^a-z0-9]", Pattern.CASE_INSENSITIVE);
        _upperCasePattern = Pattern.compile("[A-Z]");
        _lowerCasePattern = Pattern.compile("[a-z]");
        _digitPattern = Pattern.compile("[0-9]");
    }

    public List<String> validatePassword(final CharSequence password) {
        final List<String> errors = new ArrayList<>();

        if (password.length() < 8) {
            errors.add("Password must contain 8 or more characters.");
        }

        final Matcher specialCharacterMatcher = _specialCharacterPattern.matcher(password);
        if (! specialCharacterMatcher.find()) {
            errors.add("Password must contain at least one special character.");
        }

        final Matcher upperCaseMatcher = _upperCasePattern.matcher(password);
        if (! upperCaseMatcher.find()) {
            errors.add("Password must contain at least one uppercase character.");
        }

        final Matcher lowerCaseMatcher = _lowerCasePattern.matcher(password);
        if (! lowerCaseMatcher.find()) {
            errors.add("Password must contain at least one lowercase character.");
        }

        final Matcher digitMatcher = _digitPattern.matcher(password);
        if (! digitMatcher.find()) {
            errors.add("Password must contain at least one number.");
        }

        return errors;
    }
}
