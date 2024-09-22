package com.example.authenticationdemo;

import java.io.IOException;

import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.core.Authentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class PostAuthenticatioFilter extends OncePerRequestFilter {
    private final AuthenticationSuccessHandler authenticationSuccessHandler;

    public PostAuthenticatioFilter(AuthenticationSuccessHandler authenticationSuccessHandler){
        this.authenticationSuccessHandler = authenticationSuccessHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
                // get authentication context holder    
                SecurityContext context = SecurityContextHolder.getContext();
                
                Authentication auth = context.getAuthentication();
                
                if(auth == null || !auth.isAuthenticated()){ // jwt won't be generated
                    filterChain.doFilter(request, response);
                    return;
                }

                authenticationSuccessHandler.onAuthenticationSuccess(request, response, auth);               
                return;
            }    
}
