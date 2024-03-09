package com.security.auth.constants;

import com.security.auth.dto.Status;
import org.springframework.http.HttpStatus;


import java.util.HashMap;
import java.util.Map;

public class ErrorCodes {
    private ErrorCodes(){}
    private static final Map<Status, HttpStatus> statusMap = new HashMap<>();

    // add your error response status code here
    static{
        statusMap.put(Status.CONFLICT, HttpStatus.CONFLICT);
        statusMap.put(Status.NOT_FOUND, HttpStatus.NOT_FOUND);
        statusMap.put(Status.INTERNAL_SERVER_ERROR,HttpStatus.INTERNAL_SERVER_ERROR);
    }
    public static HttpStatus getHttpStatus(Status errorCode) {
        if(statusMap.containsKey(errorCode)){
            return statusMap.get(errorCode);
        }
        return statusMap.get(Status.INTERNAL_SERVER_ERROR);
    }
}
