package com.security.auth.service;

import com.security.auth.constants.ErrorMessages;
import com.security.auth.constants.ErrorResponseCodes;
import com.security.auth.dao.UserRepository;
import com.security.auth.dto.AuthRequest;
import com.security.auth.dto.AuthResponse;
import com.security.auth.dto.AuthStatus;
import com.security.auth.dto.Status;
import com.security.auth.exceptions.DBException;
import com.security.auth.model.User;
import com.security.auth.response.Response;
import com.security.auth.response.ResponseBuilder;
import com.security.auth.util.JwtUtils;
import jakarta.persistence.PersistenceException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;


@Slf4j
@Service
public class AuthServiceImpl implements AuthService {
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

        var authToken = new UsernamePasswordAuthenticationToken(username, password);

        // get the authenticate object
        Authentication authenticate = null;
        try {
            authenticate = authenticationManager.authenticate(authToken);
        } catch (Exception ex) {
            log.error(ex.getMessage());
        }

        // generate jwt token
        assert authenticate != null;
        var jwtToken = JwtUtils.generateToken(((UserDetails) (authenticate.getPrincipal())).getUsername());

        return ResponseBuilder.<AuthResponse>builder()
                .success(true)
                .response(new AuthResponse(jwtToken, AuthStatus.LOGIN_SUCCESS))
                .build();
    }

    @Override
    public Response signup(AuthRequest authRequest) {
        String username = authRequest.username();
        String password = authRequest.password();
        String name = authRequest.name();

        // check if user exists
        if (userRepository.existsByUsername(username)) {
            String message = String.format("User with userId: %s already exists", username);
            throw new DBException(message, ErrorResponseCodes.CONFLICT, Status.CONFLICT);
        }
        // persist user to database
        persistUserToDB(username, password, name);

        // generate jwt token
        var jwtToken = JwtUtils.generateToken(username);
        log.info("User added to db successfully, returning the response with jwt token: {}", jwtToken);
        return ResponseBuilder.<AuthResponse>builder()
                .success(false)
                .response(new AuthResponse(jwtToken, AuthStatus.USER_CREATED_SUCCESSFULLY))
                .build();
    }

    @Override
    public Response validateToken() {
        return null;
    }

    private void persistUserToDB(String username, String password, String name) {
        // Encode password
        var encodedPassword = passwordEncoder.encode(password);

        // Create Authority for user.
        var grantedAuthority = new ArrayList<GrantedAuthority>();
        grantedAuthority.add(new SimpleGrantedAuthority("ROLE_USER"));

        var user = User.builder()
                .username(username)
                .password(encodedPassword)
                .name(name)
                .authorities(grantedAuthority)
                .build();

        // persists user
        try {
            log.info("Adding user {} to db.", username);
            userRepository.save(user);
        } catch (PersistenceException ex) {
            log.error("Error creating user. {}", ex.getMessage());
            throw new DBException(ErrorMessages.INTERNAL_SERVER_ERROR, ErrorResponseCodes.INTERNAL_SERVER_ERROR, Status.INTERNAL_SERVER_ERROR);
        }
    }

}
