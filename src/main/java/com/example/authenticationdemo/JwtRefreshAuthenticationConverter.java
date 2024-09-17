package com.example.authenticationdemo;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.util.StringUtils;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;

public class JwtRefreshAuthenticationConverter implements AuthenticationConverter {
/**
 * Converts from a HttpServletRequest to {@link Authentication} 
 * Our approach is more aggresive as we are assumming that the resquest is indeeed to the refresh path
 */

    private static final String REFRESH_COOkIE = "refresh";

    private final JwtUtil jwtUtil;

    public JwtRefreshAuthenticationConverter(JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }

    /**
     * Converts a HttpServlet request !!!to a refresh path!!! to an Authentication
     */
    @Override
    public Authentication convert(HttpServletRequest request) throws AuthenticationException {
    
        // get refresh cookie
        Cookie[] cookies = request.getCookies();
        
        if(cookies == null)
            throw new BadCredentialsException("failed generating a new access token as refresh cookie wasn't present");

        Cookie cookie = Arrays.stream(cookies).filter(c->c.getName().equals(REFRESH_COOkIE)).findFirst()
            .orElseThrow(()->{return new BadCredentialsException("failed generating a new access token as refresh cookie wasn't present");});
        
        try{
            // when the user has provided a refresh token
            String token =  cookie.getValue();
            Map<String, ?> claims = jwtUtil.getClaims(token);
            Object rolesObject = claims.get("roles");
            
            
            List<String> roles = ((List<String>)((List<?>) rolesObject));
            return UsernamePasswordAuthenticationToken
                    .authenticated(claims.get("username"), token,
                    roles.stream().map(r->new SimpleGrantedAuthority((String)r)).collect(Collectors.toList()));
        } catch(JwtException| IllegalArgumentException |ClassCastException ex) {
            throw new BadCredentialsException(ex.getMessage());   
        }
    }
}
