package com.lkc1009.server.exception;

import org.springframework.security.core.AuthenticationException;

public class AuthenticationSecurityException extends AuthenticationException {
    public AuthenticationSecurityException(String message) {
        super(message);
    }
}
