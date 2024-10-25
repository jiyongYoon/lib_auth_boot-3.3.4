package com.example.auth_oauth2_jwt.security.filter;

import com.auth0.jwt.interfaces.DecodedJWT;
import com.example.auth_oauth2_jwt.security.config.SecurityConfig;
import com.example.auth_oauth2_jwt.security.service.UserDetailsImpl;
import com.example.auth_oauth2_jwt.dto.UserDto;
import com.example.auth_oauth2_jwt.entity.UserEntity;
import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import com.example.auth_oauth2_jwt.security.jwt.dto.GenerateJwtRequest;
import com.example.auth_oauth2_jwt.security.jwt.util.JwtDecoder;
import com.example.auth_oauth2_jwt.security.jwt.util.JwtGenerator;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Arrays;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import java.io.IOException;

import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.*;


@Slf4j
public class JwtAuthorizationFilter extends BasicAuthenticationFilter {
    private final RefreshTokenStorage refreshTokenStorage;

    public JwtAuthorizationFilter(AuthenticationManager authenticationManager, RefreshTokenStorage refreshTokenStorage) {
        super(authenticationManager);
        this.refreshTokenStorage = refreshTokenStorage;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        log.info("================ JwtAuthorizationFilter ================");

        if (SecurityConfig.NOT_AUTHORIZATION_API_LIST.contains(request.getRequestURI())) {
            log.info("authorization pass api. request = {}", request.getRequestURI());
            super.doFilterInternal(request, response, filterChain);
            return;
        }

        String authorization = null;

        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            log.info("cookie null");
            super.doFilterInternal(request, response, filterChain);
            return;
        }

        if (Arrays.asList(cookies).stream().noneMatch(cookie -> cookie.getName().equals(HttpHeaders.AUTHORIZATION))) {
            log.info("Authorization cookie doesn't exist");
            super.doFilterInternal(request, response, filterChain);
            return;
        }

        for (Cookie cookie : cookies) {

            System.out.println("exist cookie: " + cookie.getName() + " / " + cookie.getValue());
            if (cookie.getName().equals(HttpHeaders.AUTHORIZATION)) {

                authorization = cookie.getValue();
            }
        }

//        //Authorization 헤더 검증
//        if (authorization == null) {
//            log.info("token null");
//            filterChain.doFilter(request, response);
//
//            //조건이 해당되면 메소드 종료 (필수)
//            return;
//        }
//        String jwt = authorization.substring(TOKEN_PREFIX.length());

        String jwt = authorization;
        log.info("jwt 값이 있는 요청, {}", jwt);

        // 서명 검사
        DecodedJWT decodedJWT = JwtDecoder.validateSignature(jwt);
        // 유효기간 검사
        boolean isExpired = JwtDecoder.isExpired(jwt);
        if (isExpired) {
            log.info("서명은 유효하나 토큰이 만료됨");
            String requestRefreshToken = request.getHeader(REFRESH_TOKEN_HEADER);
            if (requestRefreshToken == null) {
                throw new RuntimeException(
                        "Access Token의 유효기간이 만료되었으니 가지고있는 RefreshToken을 'Refresh_Token' Header에 넣어서 보내주세요.");
            } else {
                String serverRefreshToken = refreshTokenStorage.findRefreshTokenByAccessToken(jwt)
                        .orElseThrow(() -> new RuntimeException(
                                "해당 Access Token에 대한 Refresh Token 발급이 완료되었습니다. 새로 로그인하세요."));
                JwtDecoder.validateSignature(requestRefreshToken);
                if (requestRefreshToken.equals(serverRefreshToken)) {
                    refreshTokenStorage.removeToken(jwt);

                    String newAccessToken = JwtGenerator.generateAccessToken(GenerateJwtRequest.builder()
                            .userId(decodedJWT.getClaim(CLAIM_USER_ID).asLong())
                            .userEmail(decodedJWT.getClaim(CLAIM_USER_NAME).asString())
                            .userRole(decodedJWT.getClaim(CLAIM_USER_ROLE).asString())
                            .build());
                    String newRefreshToken = JwtGenerator.generateRefreshToken();

                    refreshTokenStorage.saveAccessAndRefreshToken(newAccessToken, newRefreshToken);

                    log.info("access & refresh token 재발급 완료!");

                    response.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + newAccessToken);
                    response.addHeader(REFRESH_TOKEN_HEADER, newRefreshToken);
                } else {
                    throw new RuntimeException("말도 안됨. 서버 내부 로직 오류일수밖에 없음.");
                }
            }
        } else {
            log.info("서명은 유효하며 토큰이 만료되지 않음");
        }

        injectAuthenticationInSecurityContext(decodedJWT);
//        doFilter(request, response, filterChain);

        super.doFilterInternal(request, response, filterChain);
    }

    private void injectAuthenticationInSecurityContext(DecodedJWT decodedJWT) {
        UserEntity loginUser = UserEntity.builder()
                .id(decodedJWT.getClaim(CLAIM_USER_ID).asLong())
                .email(decodedJWT.getClaim(CLAIM_USER_NAME).asString())
                .role(decodedJWT.getClaim(CLAIM_USER_ROLE).asString())
                .build();
        UserDetailsImpl userDetails = new UserDetailsImpl(UserDto.toDto(loginUser));
        Authentication authentication = new UsernamePasswordAuthenticationToken(
                userDetails,
                userDetails.getPassword(),
                userDetails.getAuthorities()
        );
        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
