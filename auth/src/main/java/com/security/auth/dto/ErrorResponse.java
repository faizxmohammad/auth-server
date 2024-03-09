package com.security.auth.dto;

public record ErrorResponse(String message, String errorCode, Status status) {
}
