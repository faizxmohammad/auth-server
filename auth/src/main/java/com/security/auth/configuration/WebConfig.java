package com.security.auth.configuration;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
@EnableWebMvc
@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry corsRegistry) {
        corsRegistry.addMapping("/**")
                .allowedOrigins("http://localhost:8080/api/auth/login", "http://localhost:8080/api/auth/sign-up")
                .allowedHeaders("Content-Type")
                .allowedMethods("GET", "PUT", "POST", "DELETE")
                .allowCredentials(true);


    }

}
