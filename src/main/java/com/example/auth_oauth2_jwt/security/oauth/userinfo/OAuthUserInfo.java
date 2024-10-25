package com.example.auth_oauth2_jwt.security.oauth.userinfo;

import com.example.auth_oauth2_jwt.security.oauth.OAuth2Provider;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class OAuthUserInfo {
    private String userEmail;
    private String userPasswordNotEncoded;
    private String userRole;
    private OAuth2Provider oAuth2Provider;
}
