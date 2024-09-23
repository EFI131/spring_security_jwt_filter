package com.example.authenticationdemo;

import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;


@RestController
public class AuthController {

    @Autowired
    private JwtUtil jwtUtil;

    @GetMapping("/refresh")
    public String getMethodName(@CookieValue(name="refresh", defaultValue="") String token) {
        if("".equals(token)){
            throw new IllegalArgumentException("No refresh token provided");
        }

        // check if it's a refresh token
        if(!"refresh".equals(jwtUtil.getClaims(token).get("type"))){
            throw new IllegalArgumentException("No refresh token provided");
        }

        Object rolesObject = jwtUtil.getClaims(token).get("roles");
        List<String> roles = (List<String>)rolesObject;

        String refresh = jwtUtil.getJwtFor(jwtUtil.getSub(token), roles.stream().collect(Collectors.toSet()));

        return String.format("{\"token\":%s}", refresh);        
    }
}
