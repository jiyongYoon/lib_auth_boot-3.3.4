package com.example.auth_oauth2_jwt.security.oauth;

public enum OAuth2Provider {
    APP("app"),
    GOOGLE("google"),
    KAKAO("kakao"),
    NAVER("naver"),
    ;

    OAuth2Provider(String value) {
        this.value = value;
    }

    private final String value;

    public String getValue() {
        return value;
    }

    public static OAuth2Provider getProvider(String provider) {
        for (OAuth2Provider value : OAuth2Provider.values()) {
            if (value.getValue().equals(provider)) {
                return value;
            }
        }
        throw new RuntimeException("provider does not exist!");
    }
}
