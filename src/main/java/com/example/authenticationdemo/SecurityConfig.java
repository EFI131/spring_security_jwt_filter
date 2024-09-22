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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Autowired 
    private JwtUtil jwtUtil;
    
    @Autowired
    private CustomAuthenticationEntryPoint customAuthenticationEntryPoint;
    
    @Autowired
    private AuthenticationSuccessHandlerWithJwt authenticationSuccessHandler;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        return http.authorizeHttpRequests( 
            auth -> auth 
            .requestMatchers("/private").authenticated()
            .requestMatchers("/public").permitAll()
            .requestMatchers("/refresh").permitAll()
            .requestMatchers("/error").permitAll()
            // in spring security 3.x all other reqests are rejected
        ).exceptionHandling(auth->auth.authenticationEntryPoint(customAuthenticationEntryPoint))
        .httpBasic(Customizer.withDefaults())
        .addFilterAfter(new PostAuthenticatioFilter(authenticationSuccessHandler), BasicAuthenticationFilter.class)
        // adding before AnonymousFilterAuthentication to preserve default behaviour
        .addFilterBefore(new JwtFilter(jwtUtil, customAuthenticationEntryPoint), AnonymousAuthenticationFilter.class)   
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
