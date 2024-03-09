package com.security.auth.dto;

public record AuthResponse(String jwtToken, AuthStatus authStatus){
}
