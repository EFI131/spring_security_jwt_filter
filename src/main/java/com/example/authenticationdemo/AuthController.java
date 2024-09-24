package com.example.authenticationdemo;

import org.springframework.web.bind.annotation.RestController;

import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;




@RestController
public class AuthController {
    
    @Autowired
    private JwtUtil jwtUtil;

    /**
     * @param authentication - A UsernamePasswordAuthenticaton token
     * @return 
     */
    @GetMapping("/auth")
    public ResponseEntity<String> auth(Authentication authentication) {
        // pblms?
        if(authentication == null || !authentication.isAuthenticated())
            throw new IllegalStateException("Unauthenticated users shouldn't be able to get here!");

        String name = authentication.getName();
        Set<String> roles = authentication.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.toSet());
        // generate token
        String jwt = jwtUtil.getJwtFor(name , roles);
        // generate refresh
        String refresh = jwtUtil.getJwtFor(name, roles, true);

        ResponseCookie jwtCookie = ResponseCookie.from("token", jwt)
                                    .httpOnly(true)
                                    .build();

        ResponseCookie refreshCookie = ResponseCookie.from("refresh-token", refresh)
                                        .httpOnly(true)
                                        .build();
    
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtCookie.toString())
                                    .header(HttpHeaders.SET_COOKIE, refreshCookie.toString())
                                        .body(authentication.getName() +  " Welcome!");
    }

    @GetMapping("/refresh")
    public ResponseEntity<String> refresh(Authentication authentication) {
        if(!(authentication instanceof JwtAuthenticationToken) || !((JwtAuthenticationToken)authentication).isRefresh())
            throw new IllegalStateException("Not a refresh token!!!");
        
        String name = authentication.getName();
        Set<String> roles = authentication.getAuthorities().stream().map(a->a.getAuthority()).collect(Collectors.toSet());

        String jwt = jwtUtil.getJwtFor(name, roles);
        ResponseCookie jwtCookie = ResponseCookie.from("token", jwt)
                                        .httpOnly(true)
                                        .build();

        return ResponseEntity.ok()
                                .header(HttpHeaders.SET_COOKIE, jwtCookie.toString())                        
                                .build();
    }
}
