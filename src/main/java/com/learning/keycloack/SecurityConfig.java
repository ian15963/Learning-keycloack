package com.learning.keycloack;

import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@AllArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.csrf(
                c -> c.disable()
                )
                .authorizeHttpRequests(
                        a -> a.anyRequest().authenticated()
                );

        http.oauth2ResourceServer(
                r -> r.jwt(
                        jwtConfigurer -> jwtConfigurer.jwkSetUri("http://localhost:8080/realms/Ian/protocol/openid-connect/certs")
                                .jwtAuthenticationConverter(jwtAuthConverter)
                )

        );
        return http.build();
    }

}
