package com.example.authenticationdemo;

import javax.crypto.SecretKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Component
public class SecretKeyProvider {
    private final SecretKey secretKey;


    public SecretKeyProvider(@Value("${jwt.secret}") String secret){
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public SecretKey getSecretKey() {
        return secretKey;
    }

    public static void main(String[] args) {
        SecretKey key = Jwts.SIG.HS256.key().build();

        // Print the encoded key in Base64 format
        System.out.println(java.util.Base64.getEncoder().encodeToString(key.getEncoded())); 
        
    }
}
