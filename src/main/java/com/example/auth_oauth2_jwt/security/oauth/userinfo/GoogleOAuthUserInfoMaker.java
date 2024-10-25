package com.example.auth_oauth2_jwt.security.oauth.userinfo;

import com.example.auth_oauth2_jwt.security.oauth.OAuth2Provider;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Component;

@Component
public class GoogleOAuthUserInfoMaker implements OAuthUserInfoMaker {

    @Override
    public OAuthUserInfo makeUserInfo(OAuth2User oAuth2User) {
        OAuthUserInfo oAuthUserInfo = new OAuthUserInfo();
        oAuthUserInfo.setUserEmail(oAuth2User.getAttribute("email"));
        oAuthUserInfo.setUserPasswordNotEncoded(oAuth2User.getAttribute("sub"));
        oAuthUserInfo.setUserRole("ROLE_USER");
        oAuthUserInfo.setOAuth2Provider(OAuth2Provider.GOOGLE);
        return oAuthUserInfo;
    }

    @Override
    public OAuth2Provider getOAuto2Provider() {
        return OAuth2Provider.GOOGLE;
    }
}
