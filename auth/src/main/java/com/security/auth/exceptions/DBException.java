package com.security.auth.exceptions;

import com.security.auth.dto.Status;
import jakarta.persistence.PersistenceException;

public class DBException extends PersistenceException {
    private final String errorCode;
    private final Status status;

    public DBException(String message, String errorCode, Status status) {
        super(message);
        this.errorCode = errorCode;
        this.status = status;
    }

    public DBException(String message, String errorCode, Status status, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
        this.status = status;
    }

    public DBException(String message) {
        super(message);
        this.errorCode = null;
        this.status = null;
    }

    public String getErrorCode() {
        return errorCode;
    }

    public Status getStatus() {
        return status;
    }

}
