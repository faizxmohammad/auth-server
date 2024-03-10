package com.security.auth.constants;

public class ErrorMessages {
    private ErrorMessages(){}
    public static  final String INTERNAL_SERVER_ERROR = "Internal server occurred. Unable to create user, Please try again. If issue still persists please contact the administrator";
    public static final String UNAUTHORIZED_INVALID_CREDENTIALS = "Invalid Credentials";
    public static final String UNAUTHORIZED = "Unauthorized request. Invalid auth token provided. You don't have permissions to consume this content";

}
