package com.example.auth_oauth2_jwt.security.filter;

import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@RequiredArgsConstructor
public class CustomFilter extends AbstractHttpConfigurer<CustomFilter, HttpSecurity> {

    private final RefreshTokenStorage refreshTokenStorage;

    @Override
    public void configure(HttpSecurity builder) {
        AuthenticationManager authenticationManager = builder.getSharedObject(AuthenticationManager.class);
        builder.addFilter(new JwtAuthenticationFilter(authenticationManager, refreshTokenStorage));
        builder.addFilter(new JwtAuthorizationFilter(authenticationManager, refreshTokenStorage));
        builder.addFilterBefore(new OAuth2LoginTokenResponseFilter(), UsernamePasswordAuthenticationFilter.class);
    }

    public HttpSecurity build() {
        return getBuilder();
    }
}
