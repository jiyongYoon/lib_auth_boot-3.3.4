package com.example.auth_oauth2_jwt.security.jwt.util;


import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.CLAIM_EXPIRED_DATE;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.CLAIM_USER_ID;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.CLAIM_USER_NAME;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.CLAIM_USER_ROLE;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.ISSUER;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.MINUTE;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.SECRET_KEY;
import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.getAlgorithm;

import com.auth0.jwt.JWT;
import com.example.auth_oauth2_jwt.security.jwt.dto.GenerateJwtRequest;
import jakarta.annotation.PostConstruct;
import java.util.Base64;
import java.util.Date;

public class JwtGenerator {


    /**
     * 초기화 시 시크릿 키 Base64 인코딩
     */
    @PostConstruct
    protected void init() {
        SECRET_KEY = Base64.getEncoder().encodeToString(SECRET_KEY.getBytes());
    }

    /**
     * JWT Access Token 생성
     */
    public static String generateAccessToken(GenerateJwtRequest generateJwtRequest) {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withClaim(CLAIM_USER_ID, generateJwtRequest.getUserId())
                .withClaim(CLAIM_USER_NAME, generateJwtRequest.getUserEmail())
                .withClaim(CLAIM_USER_ROLE, generateJwtRequest.getUserRole())
                .withClaim(CLAIM_EXPIRED_DATE, new Date(now.getTime() + MINUTE))
                .sign(getAlgorithm(SECRET_KEY));
    }

    /**
     * JWT Refresh Token 생성
     */
    public static String generateRefreshToken() {
        Date now = new Date();

        return JWT.create()
                .withIssuer(ISSUER)
                .withIssuedAt(now)
                .sign(getAlgorithm(SECRET_KEY));
    }

}
