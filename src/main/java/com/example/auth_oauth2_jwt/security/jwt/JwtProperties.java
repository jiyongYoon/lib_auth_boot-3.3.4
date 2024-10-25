package com.example.auth_oauth2_jwt.security.jwt;

import com.auth0.jwt.algorithms.Algorithm;

import javax.crypto.SecretKey;

public class JwtProperties {

    public static String SECRET_KEY = "this-is-youtube-summary-app";
    public static SecretKey ENCODED_SECRET_KEY;
    public static final String ISSUER = "youtube-summary-app";
    public static final int SEC = 1000; //milli-sec
    public static final int MINUTE = 60 * SEC;
    public static final int HOUR = 60 * MINUTE;
    public static final int DAY = 24 * HOUR;
    public static final int JWT_TOKEN_VALID_SEC = 3 * DAY;

    public static final String CLAIM_EXPIRED_DATE = "expired_date";
    public static final String CLAIM_USER_NAME = "user_name";
    public static final String CLAIM_USER_ID = "user_id";
    public static final String CLAIM_USER_ROLE = "user_role";

    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String REFRESH_TOKEN_HEADER = "Refresh_Token";

    public static Algorithm getAlgorithm(String secretKey) {
        return Algorithm.HMAC256(secretKey);
    }
}