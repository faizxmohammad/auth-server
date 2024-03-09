package com.security.auth.controller;

import com.security.auth.dto.AuthRequest;
import com.security.auth.response.Response;
import com.security.auth.service.AuthService;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/api/auth", produces = MediaType.APPLICATION_JSON_VALUE)
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
}
