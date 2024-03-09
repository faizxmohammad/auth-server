package com.security.auth.configuration;

import com.security.auth.util.JwtUtils;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

/**
 * This class will perform jwt auth filtration for every request
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // fetch token from the request
        var jwtTokenOptional = getTokenFromTheRequest(request);
        // validate JWTToken if its present
        jwtTokenOptional.ifPresent(jwtToken -> {
            // validation
            if (JwtUtils.validateToken(jwtToken)) {
                // get username from token
                var usernameOptional = JwtUtils.getUsernameFromToken(jwtToken);
                // fetch user Details with this username
                usernameOptional.ifPresent(username -> {
                    var userDetails = userDetailsService.loadUserByUsername(username);

                    // create a new authentication token
                    var authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                    // Adding details into this authenticationToken like IP
                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // Set Authentication token to security context
                    // this security context holds the details of authenticated user
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);
                });


            }
        });

        // if jwtToken is not present then do other filtration on it
        filterChain.doFilter(request, response);
    }

    private Optional<String> getTokenFromTheRequest(HttpServletRequest request) {
        // Extract auth Header and return the jwt token
        var authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (StringUtils.hasText(authHeader) && authHeader.startsWith("Bearer ")) {
            return Optional.of(authHeader.substring(7));
        }
        return Optional.empty();
    }
}
