package com.security.auth.service;

import com.security.auth.constants.ErrorMessages;
import com.security.auth.constants.ErrorResponseCodes;
import com.security.auth.dao.UserRepository;
import com.security.auth.dto.*;
import com.security.auth.exceptions.AuthException;
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

import java.util.ArrayList;
import java.util.Optional;


@Slf4j
@Service
public class AuthServiceImpl implements AuthService {
    @Autowired
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

        boolean validUser = validateUser(username, password);
        if(!validUser){
            String errorMessage = ErrorMessages.UNAUTHORIZED_INVALID_CREDENTIALS;
            String errorCode = ErrorResponseCodes.UNAUTHORIZED;
            Status status = Status.UNAUTHORIZED;
            throw new AuthException(errorMessage,errorCode,status);
        }

        var authToken = new UsernamePasswordAuthenticationToken(username, password);
        // get the authenticate object
        Authentication authenticate = this.authenticationManager.authenticate(authToken);
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
    public Response isTokenExpired(String jwtToken) {
        boolean isTokenExpired = JwtUtils.isTokenExpired(jwtToken);
        if(isTokenExpired){
            throw new AuthException(ErrorMessages.UNAUTHORIZED, ErrorResponseCodes.UNAUTHORIZED, Status.UNAUTHORIZED);
        }
        return ResponseBuilder.<ValidToken>builder().success(true).response(new ValidToken(true,Status.VALID)).build();
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
    private boolean validateUser(String username, String password) {
        // If user does not exists return false
        boolean existsByUsername = userRepository.existsByUsername(username);
        if (!existsByUsername) {
            return false;
        }
        // If user exists validate the credentials.
        Optional<User> user = userRepository.findByUsername(username);
        if (user.isPresent()) {
            String dbPassword = user.get().getPassword();
            return passwordEncoder.matches(password, dbPassword);
        }
        return false;
    }
}
