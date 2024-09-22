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
 * 2) autheticates given a jwt access token in the Authorizaiton header
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
                    /**  AuthenticationException will be thrown in case of a non conforming Autherization header and therefore this filter should appear after other forms of authentication,
                        and it's reuqires them to handle success with a success handler */
            try {
                // returns a UsernamePasswordAuthenticationToken in case of : Authrization: Bearer <token>
                // and null if not present
                Authentication auth = this.authenticationConverter.convert(request);
                
                if(auth == null){ // didn't match our requirements for jwt auth -> proceed with filter chain
                    filterChain.doFilter(request, response);
                    return;
                }

                // Set security context 
                SecurityContext securityContext = securityContextHolderStrategy.createEmptyContext();
                securityContext.setAuthentication(auth);
                securityContextHolderStrategy.setContext(securityContext);

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
