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


/**
 * The below filter:
 * 1) creates a jwt derived from a present authenticated authentication at the security context holder
 * 2) authenticates given a jwt access token in the Authorizaiton header
 * 3) creates and returns a jwt access token if given a refresh token as a value of a 'refress' cookie, and the uri is /refresh 
 */
public class JwtFilter extends OncePerRequestFilter {

    private final JwtAuthenticationConverter authenticationConverter;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    
    public JwtFilter(JwtUtil jwtUtil, AuthenticationEntryPoint authenticationEntryPoint){
        this.authenticationConverter = new JwtAuthenticationConverter(jwtUtil);
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
                securityContextHolderStrategy.setContext(securityContext);

                // proceed with filter chain
                filterChain.doFilter(request, response);
                return;

            } catch(AuthenticationException ex){
                authenticationEntryPoint.commence(request, response, ex);
                //response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
                if(this.logger.isDebugEnabled()) {
                    this.logger.error(ex.getMessage(), ex);
                }
            }
    }
}
