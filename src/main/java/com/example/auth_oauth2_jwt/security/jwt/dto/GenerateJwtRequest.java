package com.example.auth_oauth2_jwt.security.jwt.dto;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class GenerateJwtRequest {
    private Long userId;
    private String userEmail;
    private String userRole;

    @Builder
    public GenerateJwtRequest(Long userId, String userEmail, String userRole) {
        this.userId = userId;
        this.userEmail = userEmail;
        this.userRole = userRole;
    }
}
