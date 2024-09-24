package com.example.authenticationdemo;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;


import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class RefreshTokenFilter extends OncePerRequestFilter{
    
    private final RefreshAuthenticationConverter authenticationConverter;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    
    public RefreshTokenFilter(JwtUtil jwtUtil, AuthenticationEntryPoint authenticationEntryPoint){
        this.authenticationConverter = new RefreshAuthenticationConverter(jwtUtil);
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
        .getContextHolderStrategy();  

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

            try {
                // 1. simple access token in Authorization header
                Authentication auth = this.authenticationConverter.convert(request);
                
                if(auth == null){// No Authorization header with a valid jwt was found
                    if(this.logger.isTraceEnabled()){
                        this.logger.trace("Did not process authentication request since failed to find json web token in Bearer header");
                    }
                    filterChain.doFilter(request, response);
                    return;
                }

                // Set jwt derived authentication into security context holder 
                SecurityContext securityContext = securityContextHolderStrategy.createEmptyContext();
                securityContext.setAuthentication(auth);
                SecurityContextHolder.setContext(securityContext);

                // proceed with filter chain
                filterChain.doFilter(request, response);
                return;

            } catch(AuthenticationException ex){
                authenticationEntryPoint.commence(request, response, ex);
                if(this.logger.isDebugEnabled()) {
                    this.logger.error(ex.getMessage(), ex);
                }
            }
    }
}
