package com.example.auth_oauth2_jwt.security.jwt.util;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import lombok.extern.slf4j.Slf4j;

import java.util.Date;

import static com.example.auth_oauth2_jwt.security.jwt.JwtProperties.*;

@Slf4j
public class JwtDecoder {

    /**
     * JWT 토큰의 유저명 가져오기
     */
    public static String getUsernameByJwtToken(String token) throws Exception {
        DecodedJWT decodedToken = validateSignature(token);
        return decodedToken.getClaim(CLAIM_USER_NAME).asString();
    }

    public static boolean isExpired(String token) {
        Date now = new Date();
        Date tokenExpiredDate = JWT.decode(token).getClaim(CLAIM_EXPIRED_DATE).asDate();
        if (tokenExpiredDate.before(now)) {
            log.info("유효기간이 지난 토큰입니다. 유효기간: " + tokenExpiredDate);
            return true;
        }
        return false;
    }

    /**
     * JWT 토큰 validate <br>
     * 1. 서명 검사 <br>
     * 2. 구조에 따라 public으로 오픈할 가능성 높음
     */
    public static DecodedJWT validateSignature(String token) {
        JWTVerifier verifier = JWT
                .require(getAlgorithm(SECRET_KEY))
                .build();
        DecodedJWT decodedJWT = verifier.verify(token);
        log.info("검증완료!!!");
        return decodedJWT;
    }
}
