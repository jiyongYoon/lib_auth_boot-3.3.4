package com.example.auth_oauth2_jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

@AllArgsConstructor
@Getter
public enum OAuth2Provider {
    GOOGLE("google"),
    NAVER("naver"),
    ;

    private final String value;
}
