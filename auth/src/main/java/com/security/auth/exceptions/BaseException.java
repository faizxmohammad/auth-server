package com.security.auth.exceptions;

public abstract class BaseException extends RuntimeException{
    protected BaseException(String message) {
        super(message);
    }
    protected BaseException(String message, Throwable cause) {
        super(message, cause);
    }
}
