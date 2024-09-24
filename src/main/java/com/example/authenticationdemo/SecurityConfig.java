package com.example.authenticationdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter;



@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    
    @Autowired 
    private JwtUtil jwtUtil;

    // a filter chain for requests with a valid jwt
    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/private")
            .authorizeHttpRequests( 
            auth -> auth 
            .requestMatchers("/private").authenticated()
            .requestMatchers("/public").permitAll()
            .requestMatchers("/error").permitAll()
            // in spring security 3.x all other reqests are rejected
        ).exceptionHandling(auth->auth.authenticationEntryPoint(customAuthenticationEntryPoint))
        // adding before AnonymousFilterAuthentication to preserve default behaviour
        .addFilterBefore(new JwtFilter(jwtUtil, customAuthenticationEntryPoint), AnonymousAuthenticationFilter.class)
        .anonymous(a->a.disable())
        .build();
    }

    @Bean
    SecurityFilterChain authFilterChain(HttpSecurity http) throws Exception {
        return http
        .securityMatcher("/auth")
        .authorizeHttpRequests(
            auth -> auth
                .requestMatchers("/auth").authenticated()
        ).exceptionHandling(auth->auth.authenticationEntryPoint(customAuthenticationEntryPoint))
        .httpBasic(Customizer.withDefaults())
        .build();
    }

    @Bean
    SecurityFilterChain refreshFilterChain(HttpSecurity http) throws Exception {
        return http
            .securityMatcher("/refresh")
            .authorizeHttpRequests(
                auth -> auth
                    .requestMatchers("/refresh").authenticated()
            ).exceptionHandling(auth -> auth.authenticationEntryPoint(customAuthenticationEntryPoint))
            .addFilterBefore(new RefreshTokenFilter(jwtUtil, customAuthenticationEntryPoint),AnonymousAuthenticationFilter.class)
            .anonymous(a->a.disable())
            .build();
    }

    @Bean
    UserDetailsService userDetailsService() {
        UserDetails user = User.builder()
            .username("user")
            .password("{noop}password")
            .roles("USER")
            .build();
        
        UserDetails admin = User.builder()
            .username("admin")
            .password("{noop}password")
            .roles("ADMIN", "USER")
            .build();

        return new InMemoryUserDetailsManager(user, admin);
    }
}
