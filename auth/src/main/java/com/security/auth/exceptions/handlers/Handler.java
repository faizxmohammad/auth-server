package com.security.auth.exceptions.handlers;


import com.security.auth.constants.ErrorCodes;
import com.security.auth.constants.ErrorResponseCodes;
import com.security.auth.dto.ErrorResponse;
import com.security.auth.dto.Status;
import com.security.auth.exceptions.AuthException;
import com.security.auth.exceptions.DBException;
import com.security.auth.response.Response;
import com.security.auth.response.ResponseBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@ControllerAdvice
@Slf4j
public class Handler {

    @ExceptionHandler(DBException.class)
    public ResponseEntity<Response> handleDbException(DBException dbException) {
        log.error("{} Database exception occurred: \r\n  {}", getTimeStamp(), dbException.getMessage());

        String errorMessage = dbException.getMessage();
        String errorCode = dbException.getErrorCode();
        Status statusCode = dbException.getStatus();

        Response errorResponse = ResponseBuilder.<ErrorResponse>builder().success(false).response(new ErrorResponse(errorMessage, errorCode, statusCode)).build();
        return new ResponseEntity<>(errorResponse, ErrorCodes.getHttpStatus(statusCode));
    }


    @ExceptionHandler(AuthException.class)
    public ResponseEntity<Response> handleAuthException(AuthException authException) {
        log.error("{} authorization exception occurred: \r\n  {}", getTimeStamp(), authException.getMessage());

        String errorMessage = authException.getMessage();
        String errorCode = authException.getErrorCode();
        Status statusCode = authException.getStatus();

        Response errorResponse = ResponseBuilder.<ErrorResponse>builder().success(false).response(new ErrorResponse(errorMessage, errorCode, statusCode)).build();
        return new ResponseEntity<>(errorResponse, ErrorCodes.getHttpStatus(statusCode));
    }

    @ExceptionHandler(IllegalStateException.class)
    public ResponseEntity<Response> handleIllegalStateException(IllegalStateException illegalStateException) {
        log.error("{} Illegal state exception occurred: \r\n  {}", getTimeStamp(), illegalStateException.getMessage());

        String errorMessage = illegalStateException.getMessage();
        String errorCode = ErrorResponseCodes.INTERNAL_SERVER_ERROR;
        Status statusCode = Status.INTERNAL_SERVER_ERROR;

        Response errorResponse = ResponseBuilder.<ErrorResponse>builder().success(false).response(new ErrorResponse(errorMessage, errorCode, statusCode)).build();
        return new ResponseEntity<>(errorResponse, ErrorCodes.getHttpStatus(statusCode));
    }


    private String getTimeStamp() {
        LocalDateTime now = LocalDateTime.now();
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("[dd-MM-yyyy:HH:mm:ss]");
        return now.format(formatter);
    }

}
