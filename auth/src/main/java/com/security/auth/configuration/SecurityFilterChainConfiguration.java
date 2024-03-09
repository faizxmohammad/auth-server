package com.security.auth.configuration;

import com.security.auth.dao.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityFilterChainConfiguration {
    private final AuthenticationEntryPoint authenticationEntryPoint;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final UserRepository userRepository;

    public SecurityFilterChainConfiguration(AuthenticationEntryPoint authenticationEntryPoint, JwtAuthenticationFilter jwtAuthenticationFilter, UserRepository userRepository) {
        this.authenticationEntryPoint = authenticationEntryPoint;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.userRepository = userRepository;
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity httpSecurity) throws Exception {
        // Disable csrf
        httpSecurity.csrf(AbstractHttpConfigurer::disable);

        // Filter our http request using request matcher
        httpSecurity.authorizeHttpRequests(
                // Permit all requests coming to this url without any auth
                requestMatcher -> requestMatcher.requestMatchers("/api/auth/login/**")
                        .permitAll()
                // Permit all requests coming to this url without any auth
                        .requestMatchers("/api/auth/sign-up/**")
                        .permitAll()
//                // all other endpoints should be accessed by authenticated user only
                        .anyRequest()
                        .authenticated()
        );

        // Authentication Entry point
        // if any exception occurs while authenticating we will handle it here.
        httpSecurity.exceptionHandling(
                exceptionConfig -> exceptionConfig.authenticationEntryPoint(authenticationEntryPoint)
        );

        // Setting the session to stateless, since we are not storing the session
        httpSecurity.sessionManagement(
                sessionConfig -> sessionConfig.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        );

        // adding JWT authentication Filter for every request received to our endpoints
        httpSecurity.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }
}
