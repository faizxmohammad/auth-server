package com.security.auth.service;

import com.security.auth.dao.UserRepository;
import com.security.auth.dto.AuthRequest;
import com.security.auth.dto.AuthResponse;
import com.security.auth.dto.AuthStatus;
import com.security.auth.model.User;
import com.security.auth.response.Response;
import com.security.auth.response.ResponseBuilder;
import com.security.auth.util.JwtUtils;
import jakarta.persistence.PersistenceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class AuthServiceImpl implements AuthService{

    private final AuthenticationManager authenticationManager;
    private final PasswordEncoder passwordEncoder;
    private final UserRepository userRepository;

    public AuthServiceImpl(AuthenticationManager authenticationManager, PasswordEncoder passwordEncoder, UserRepository userRepository) {
        this.authenticationManager = authenticationManager;
        this.passwordEncoder = passwordEncoder;
        this.userRepository = userRepository;
    }

    @Override
    public Response login(AuthRequest authRequest) {
        String username = authRequest.username();
        String password = authRequest.password();

        var authToken = new UsernamePasswordAuthenticationToken(username,password);
        // get the authenticate object
       var authenticate =  authenticationManager.authenticate(authToken);

        // generate jwt token
        var jwtToken = JwtUtils.generateToken(((UserDetails)(authenticate.getPrincipal())).getUsername());

        return ResponseBuilder.<AuthResponse>builder()
                .error(false)
                .response(new AuthResponse(jwtToken, AuthStatus.LOGIN_SUCCESS))
                .build();
    }

    @Override
    public Response signup(AuthRequest authRequest) {
        String username = authRequest.username();
        String password = authRequest.password();
        String name = authRequest.name();

        // check if user exists
        if(userRepository.existsByUsername(username)){
            throw new RuntimeException(String.format("User already exists with the username: %s",username));
        }
        // Encoded password
        var encodedPassword = passwordEncoder.encode(password);

        // Create Authority for user.
        var grantedAuthority = new ArrayList<GrantedAuthority>();
        grantedAuthority.add(new SimpleGrantedAuthority("ROLE_USER")) ;

        // create user
        var user = User.builder()
                .username(username)
                .password(encodedPassword)
                .name(name)
                .authorities(grantedAuthority)
                .build();


        // save user
        try{
            userRepository.save(user);
        }catch(PersistenceException ex){
            log.error("Error creating user. {}", ex.getMessage());
        }

        // generate jwt token
        var jwtToken = JwtUtils.generateToken(username);


        return ResponseBuilder.<AuthResponse>builder()
                .error(false)
                .response(new AuthResponse(jwtToken, AuthStatus.USER_CRATED_SUCCESSFULLY))
                .build();
    }
}
