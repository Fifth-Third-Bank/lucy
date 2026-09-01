package com.example.ledger.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Resource-server security wiring for ledger-api.
 *
 * <p>The API is stateless and token-only: every request must carry a JWT
 * minted by the demo realm. Issuer, audience, signature, and expiry
 * validation are all handled by the oauth2ResourceServer support using
 * the settings in application.yml. Method-level {@code @PreAuthorize}
 * checks in the controllers enforce per-route scopes on top of this.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiFilterChain(HttpSecurity http) throws Exception {
        http
            // CSRF protection is not applicable to a stateless bearer-token
            // API with no cookie-based sessions.
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session ->
                    session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                    // Health probes are the only unauthenticated surface.
                    .requestMatchers("/actuator/health/**").permitAll()
                    .anyRequest().authenticated())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
