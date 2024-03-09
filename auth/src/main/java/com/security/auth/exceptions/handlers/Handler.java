package com.security.auth.exceptions.handlers;


import com.fasterxml.jackson.databind.util.JSONPObject;
import com.security.auth.constants.ErrorCodes;
import com.security.auth.dto.ErrorResponse;
import com.security.auth.dto.Status;
import com.security.auth.exceptions.DBException;
import com.security.auth.response.Response;
import com.security.auth.response.ResponseBuilder;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Slf4j
public class Handler {

    @ExceptionHandler(DBException.class)
    public ResponseEntity<Response> handleDbException(DBException dbException) {
        log.error("Database exception occurred: \r\n  {}", dbException.getMessage());

        String errorMessage = dbException.getMessage();
        String errorCode = dbException.getErrorCode();
        Status statusCode = dbException.getStatus();

        Response errorResponse = ResponseBuilder.<ErrorResponse>builder()
                .success(false)
                .response(new ErrorResponse(errorMessage, errorCode, statusCode))
                .build();
        return new ResponseEntity<>(errorResponse, ErrorCodes.getHttpStatus(statusCode));

    }
}
