package com.authserver.config.exception;

import org.springframework.security.core.AuthenticationException;

public class OAuthException extends AuthenticationException {


    public OAuthException(String msg) {
        super(msg);
    }
}
