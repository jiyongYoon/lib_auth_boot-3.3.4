package com.example.auth_oauth2_jwt.security.jwt.util;

import jakarta.servlet.http.Cookie;

public class CookieGenerator {

    private static final int ONE_HOUR = 60 * 60;

    public static Cookie create(String key, String value) {

        Cookie cookie = new Cookie(key, value);
        cookie.setMaxAge(ONE_HOUR); // second 단위
        //cookie.setSecure(true); // https에서만
        cookie.setPath("/");
        cookie.setHttpOnly(true); // javascript가 쿠키정보를 가져가지 못하도록

        return cookie;
    }
}
