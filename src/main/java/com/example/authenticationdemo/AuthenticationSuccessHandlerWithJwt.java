package com.example.authenticationdemo;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class AuthenticationSuccessHandlerWithJwt implements AuthenticationSuccessHandler{

    private JwtUtil jwtUtil;

    public AuthenticationSuccessHandlerWithJwt(JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
            Authentication authentication) throws IOException, ServletException {
                // generate jwt token and a refresh token
                String token = jwtUtil
                    .getJwtFor(authentication.getName(), 
                                        authentication.getAuthorities().stream()
                                                        .map(a->a.getAuthority())
                                                        .collect(Collectors.toSet()));
                
                Cookie cookie = new Cookie("token", token);
                cookie.setHttpOnly(true);
                response.addCookie(cookie); 
    }
}
