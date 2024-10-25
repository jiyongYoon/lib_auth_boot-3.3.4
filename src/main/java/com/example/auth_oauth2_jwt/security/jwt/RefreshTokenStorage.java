package com.example.auth_oauth2_jwt.security.jwt;

import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

@Repository
public class RefreshTokenStorage {

    private final Map<String, String> accessToRefreshMap = new HashMap<>();

    public void saveAccessAndRefreshToken(String accessToken, String refreshToken) {
        accessToRefreshMap.put(accessToken, refreshToken);
    }

    public Optional<String> findRefreshTokenByAccessToken(String accessToken) {
        return Optional.ofNullable(accessToRefreshMap.getOrDefault(accessToken, null));
    }

    public void removeToken(String accessToken) {
        accessToRefreshMap.remove(accessToken);
    }

    public Map<String, String> getInstance() {
        return accessToRefreshMap;
    }
}
