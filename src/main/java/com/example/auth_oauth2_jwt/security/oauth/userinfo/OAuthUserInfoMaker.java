package com.example.auth_oauth2_jwt.security.oauth.userinfo;

import com.example.auth_oauth2_jwt.security.oauth.OAuth2Provider;
import org.springframework.security.oauth2.core.user.OAuth2User;

public interface OAuthUserInfoMaker {

    OAuthUserInfo makeUserInfo(OAuth2User oAuth2User);
    OAuth2Provider getOAuto2Provider();
}
