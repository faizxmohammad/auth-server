package com.security.auth.service;

import com.security.auth.dto.AuthRequest;
import com.security.auth.response.Response;

public interface AuthService {
    Response login(AuthRequest authRequest);
    Response signup(AuthRequest authRequest);
    Response isTokenExpired(String jwtToken);

}
