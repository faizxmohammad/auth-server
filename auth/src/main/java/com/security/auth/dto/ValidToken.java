package com.security.auth.dto;

public record ValidToken(boolean isValid, Status status) {
}
