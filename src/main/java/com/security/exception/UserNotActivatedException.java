package com.security.exception;

import org.springframework.security.core.AuthenticationException;

public class UserNotActivatedException extends AuthenticationException {

    public UserNotActivatedException(String explanation) {
        super(explanation);
    }

    public UserNotActivatedException(String message, Throwable throwable) {
        super(message, throwable);
    }

}
