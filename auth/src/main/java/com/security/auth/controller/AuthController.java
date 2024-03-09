package com.security.auth.controller;

import com.security.auth.dto.AuthRequest;
import com.security.auth.response.Response;
import com.security.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public ResponseEntity<Response> login(@RequestBody AuthRequest authRequest) {
        Response response = authService.login(authRequest);
        return new ResponseEntity<>(response, HttpStatus.OK);
    }

    @PostMapping("/sign-up")
    public ResponseEntity<Response> signup(@RequestBody AuthRequest authRequest) {
        Response response = authService.signup(authRequest);
        return new ResponseEntity<>(response, HttpStatus.CREATED);
    }


    @PostMapping("/validate-token")
    public ResponseEntity<Response> validateToken(@RequestHeader("Authorization") String jwtToken){
        return null;
    }
}
