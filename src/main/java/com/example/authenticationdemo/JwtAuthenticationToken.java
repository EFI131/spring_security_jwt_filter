package com.example.authenticationdemo;

import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class JwtAuthenticationToken extends UsernamePasswordAuthenticationToken{

    private String type;
    public JwtAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public JwtAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities){
        super(principal, credentials, authorities);
    }

    public JwtAuthenticationToken(Object principal, Object credentials,
            Collection<? extends GrantedAuthority> authorities, String type) {
        super(principal, credentials, authorities);
        this.type = type;
    }

    public static JwtAuthenticationToken authenticated(Object principal, Object credentials,
    Collection<? extends GrantedAuthority> authorities, String type){
        return new JwtAuthenticationToken(principal, credentials, authorities, type);
    }

    public String getType() {
        return type;
    }

    public boolean isRefresh(){
        return "refresh".equals(type);
    }
}
