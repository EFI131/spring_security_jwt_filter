package com.example.authenticationdemo;

import java.io.IOException;
import java.util.stream.Collectors;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


/**
 * The below filter:
 * 1) creates a jwt derived from a present authenticated authentication at the security context holder
 * 2) autheticates given a jwt access token in the Authorizaiton header
 * 3) creates and returns a jwt access token if given a refresh token as a value of a 'refress' cookie, and the uri is /refresh 
 */
public class JwtFilter extends OncePerRequestFilter {

    public static final String REFRESH_URL = "/refresh";
    
    private final JwtUtil jwtUtil;
    private final JwtAuthenticationConverter authenticationConverter;
    private final JwtRefreshAuthenticationConverter jwtRefreshAuthenticationConverter;
    private final AuthenticationEntryPoint authenticationEntryPoint;
    
    public JwtFilter(JwtUtil jwtUtil, AuthenticationEntryPoint authenticationEntryPoint){
        this.jwtUtil = jwtUtil;
        this.authenticationConverter = new JwtAuthenticationConverter(jwtUtil);
        this.jwtRefreshAuthenticationConverter = new JwtRefreshAuthenticationConverter(jwtUtil);
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
        .getContextHolderStrategy();  

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
            
            boolean refresh = false;

            try {
                // 1. simple access token in Authorization header
                Authentication auth = this.authenticationConverter.convert(request);
                
                if(auth == null){// No Authorization header with a valid jwt was found
                    this.logger.trace("Did not process authentication request since failed to find json web token in Bearer header");

                    refresh = isRefreshRequest(request);
                    if(refresh){
                    // 2. Authentication derived from refresh token
                        auth = this.jwtRefreshAuthenticationConverter.convert(request);
                    }
                    else {
                    // 3. login authentication
                        auth = securityContextHolderStrategy.getContext().getAuthentication();
                    }


                    // Authentication acquired through step 2 or 3
                    if((auth != null && auth.isAuthenticated())){ 

                        // generate jwt and write into response
                        String jwt = jwtUtil.getJwtFor(auth.getName(), 
                                                    auth.getAuthorities().stream()
                                                    .map(a->a.getAuthority())
                                                    .collect(Collectors.toSet()));
                        
                        // store in jwt cookie
                        Cookie jwtCookie = new Cookie("token", jwt );
                        jwtCookie.setHttpOnly(true);
                        response.addCookie(jwtCookie);

                        if(!refresh){
                            // if we got it through authentication we need to generate and send a refresh token
                            String refreshToken = jwtUtil.getJwtFor(auth.getName(), 
                            auth.getAuthorities().stream()
                            .map(a->a.getAuthority())
                            .collect(Collectors.toSet()), true);
                            
                            Cookie refreshCookie = new Cookie("refresh", refreshToken );
                            jwtCookie.setHttpOnly(true);
                            response.addCookie(refreshCookie); 
                        }

                                            
                        if(this.logger.isDebugEnabled()) {
                            this.logger.debug(LogMessage.format("Set SecurityContextHolder to %s", auth));
                        }

                        response.flushBuffer();
                        return;
                    }
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

    private boolean isRefreshRequest(HttpServletRequest request) {
        return request.getRequestURI().equals(REFRESH_URL);
    }

}
