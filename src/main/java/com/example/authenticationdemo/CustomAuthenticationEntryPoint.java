package com.example.authenticationdemo;

import java.io.IOException;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * A basic Autentication entry point
 */
@Component
public class CustomAuthenticationEntryPoint implements AuthenticationEntryPoint{
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response,
                        AuthenticationException authException) throws IOException {

        // Set custom response status
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        // Set custom content type
        response.setContentType("application/json");

        // Create a custom message
        String message = "{\"error\": \"Unauthorized access - Please authenticate to access this resource.\"}";

        // Write the custom message to the response body
        response.getWriter().write(message);
    }
}
