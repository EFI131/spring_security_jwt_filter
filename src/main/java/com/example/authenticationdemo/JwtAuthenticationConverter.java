package com.example.authenticationdemo;

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
import jakarta.servlet.http.HttpServletRequest;

public class JwtAuthenticationConverter implements AuthenticationConverter {
    /**
     * Converts from a HttpServletRequest to {@link Authentication} unclear what kind right now
     */

    private static final String AUTHENTICATION_SCHEME_BEARER = "Bearer";

    private final JwtUtil jwtUtil;

    public JwtAuthenticationConverter(JwtUtil jwtUtil){
        this.jwtUtil = jwtUtil;
    }

    /**
     * Converts a HttpServlet request to an Authentication
     */
    @Override
    public Authentication convert(HttpServletRequest request) throws AuthenticationException {
    
        // get Autorization header
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        // if the header doesn't exist we won't convert
        if(header == null){
            return null;
        }
        header = header.trim();
        if(!StringUtils.startsWithIgnoreCase(header, AUTHENTICATION_SCHEME_BEARER)) {
            return null;
        }
        if(header.equalsIgnoreCase(AUTHENTICATION_SCHEME_BEARER)){
            throw new BadCredentialsException("Empty json web token");
        }

        try{
        // when the user has provides a token
        String token =  header.substring(7);
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
