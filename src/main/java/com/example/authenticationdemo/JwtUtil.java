package com.example.authenticationdemo;

import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Set;

import org.springframework.stereotype.Component;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.UnsupportedJwtException;

/**
 * Jwt utility class, act as an entry point to jwt related manipulations
 */

@Component
public class JwtUtil {
    private final SecretKeyProvider secretKeyProvider;
    private final JwtParser parser;

    private final long tokenDurationInSeconds = 7 * 60;
    private final long refreshDurationInSeconds = 15 * 60;

    public JwtUtil(SecretKeyProvider secretKeyProvider) {
        this.secretKeyProvider = secretKeyProvider;
        this.parser = Jwts.parser().verifyWith(secretKeyProvider.getSecretKey()).build();
    }

    /** Get a map representing claims */
    public Map<String, ?> getClaims(String token) 
    throws UnsupportedJwtException, JwtException, IllegalArgumentException {
            return (Map<String, ?>)parser.
                parseSignedClaims(token).getPayload();
    }


    /**
     * Create a jwe given username and a set of roles.
     * @param roles user's roles
     * @return Jwe string
     */
    public String getJwtFor(String username, Set<String> roles ){
        Instant creation = Instant.now();
        Instant expiration = creation.plusSeconds(tokenDurationInSeconds);
        return Jwts.builder()
                    .subject(username)
                    .claim("roles", roles)
                    .claim("type", "access")
                    .issuedAt(Date.from(creation))
                    .expiration(Date.from(expiration))
                    .signWith(secretKeyProvider.getSecretKey())
                    .compact();
    }

    public String getJwtFor(String username, Set<String> roles, boolean refresh) {
        Instant creation = Instant.now();

        Instant expiration =  refresh ? creation.plusSeconds(refreshDurationInSeconds): creation.plusSeconds(tokenDurationInSeconds);
        return Jwts.builder()
                    .subject(username)
                    .claim("roles", roles)
                    .claim("type", refresh? "refresh" : "access")
                    .issuedAt(Date.from(creation))
                    .expiration(Date.from(expiration))
                    .signWith(secretKeyProvider.getSecretKey())
                    .compact();
    }

    public String getSub(String token) {
        return parser.parseSignedClaims(token).getPayload().getSubject();
    }
}
