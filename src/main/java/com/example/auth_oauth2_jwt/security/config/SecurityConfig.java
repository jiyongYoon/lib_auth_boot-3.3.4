package com.example.auth_oauth2_jwt.security.config;

import com.example.auth_oauth2_jwt.global.Domain;
import com.example.auth_oauth2_jwt.security.filter.CustomFilter;
import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import com.example.auth_oauth2_jwt.security.oauth.OAuth2MemberSuccessHandler;
import com.example.auth_oauth2_jwt.security.service.CustomOAuth2UserServiceImpl;
import jakarta.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Collections;

@Configuration
@EnableWebSecurity//(debug = true)
@RequiredArgsConstructor
public class SecurityConfig {

    private final CustomOAuth2UserServiceImpl customOAuth2UserServiceImpl;
    private final RefreshTokenStorage refreshTokenStorage;

    public static final List<String> NOT_AUTHORIZATION_API_LIST = new ArrayList<>();

    static {
        NOT_AUTHORIZATION_API_LIST.addAll(
            Arrays.asList(
                "/api/signup",
                "/oauth/login"
            )
        );
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        //cors
        http
                .cors(corsCustomizer -> corsCustomizer.configurationSource(new CorsConfigurationSource() {

                    @Override
                    public CorsConfiguration getCorsConfiguration(HttpServletRequest request) {

                        CorsConfiguration configuration = new CorsConfiguration();

                        configuration.setAllowedOrigins(Collections.singletonList(Domain.FRONT));
                        configuration.setAllowedMethods(Collections.singletonList("*"));
                        configuration.setAllowCredentials(true);
                        configuration.setAllowedHeaders(Collections.singletonList("*"));
                        configuration.setMaxAge(3600L);

                        configuration.setExposedHeaders(Collections.singletonList("Set-Cookie"));
                        configuration.setExposedHeaders(Collections.singletonList(HttpHeaders.AUTHORIZATION));

                        return configuration;
                    }
                }));


        //csrf disable
        http
                .csrf((auth) -> auth.disable());

        //From 로그인 방식 disable
        http
                .formLogin((auth) -> auth.disable());

        //HTTP Basic 인증 방식 disable
        http
                .httpBasic((auth) -> auth.disable());

        // JwtFilter가 포함된 CustomFilter 추가 (https://docs.spring.io/spring-security/reference/servlet/configuration/java.html#jc-custom-dsls)
        http
                .with(new CustomFilter(refreshTokenStorage), CustomFilter::build);

        //oauth2
        http
                .oauth2Login((oauth2) -> oauth2
//                        .loginPage("/oauth2/login")
                        .userInfoEndpoint((userInfoEndpointConfig) -> userInfoEndpointConfig
                                .userService(customOAuth2UserServiceImpl))
                        .successHandler(new OAuth2MemberSuccessHandler(refreshTokenStorage))
                );

        //경로별 인가 작업
        http
                .authorizeHttpRequests((auth) -> auth
                        .requestMatchers("/error").permitAll()
//                        .requestMatchers("/oauth2/login").permitAll()
                        .requestMatchers("/login").permitAll() // oauth login 호출 버튼이 있는 페이지
                        .requestMatchers("/api/login").permitAll() // 일반 로그인 api
                        .requestMatchers("/api/signup").permitAll() // 일반 회원가입 api
                        .requestMatchers("/api/token").permitAll() // 서버에 저장되어있는 refresh token 확인
                        .requestMatchers("/api/oauth-jwt").permitAll() // oauth login 후 토큰정보를 가진 redirect url 을 받아서 쿠키(헤더)에 추가하는 페이지
                        .requestMatchers("/api/context").permitAll() // 현재 context에 있는 정보 확인
                        .anyRequest().authenticated());

        //세션 설정 : STATELESS
        http
                .sessionManagement((session) -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        return http.build();
    }
}