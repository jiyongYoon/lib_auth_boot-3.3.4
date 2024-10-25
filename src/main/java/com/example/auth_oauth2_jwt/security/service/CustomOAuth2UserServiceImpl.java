package com.example.auth_oauth2_jwt.security.service;

import com.example.auth_oauth2_jwt.dto.*;
import com.example.auth_oauth2_jwt.security.oauth.OAuth2Provider;
import com.example.auth_oauth2_jwt.entity.UserEntity;
import com.example.auth_oauth2_jwt.repository.UserRepository;
import com.example.auth_oauth2_jwt.security.oauth.userinfo.OAuthUserInfo;
import com.example.auth_oauth2_jwt.security.oauth.userinfo.OAuthUserInfoMaker;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@Service
@Slf4j
public class CustomOAuth2UserServiceImpl extends DefaultOAuth2UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    private final Map<OAuth2Provider, OAuthUserInfoMaker> oAuthUserInfoMakerMap = new HashMap<>();

    public CustomOAuth2UserServiceImpl(Set<OAuthUserInfoMaker> oAuthUserInfoMakerSet,
                                       UserRepository userRepository,
                                       PasswordEncoder passwordEncoder) {
        oAuthUserInfoMakerSet.forEach(
                oAuthUserInfoMaker -> oAuthUserInfoMakerMap.put(
                        oAuthUserInfoMaker.getOAuto2Provider(),
                        oAuthUserInfoMaker
                )
        );
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        log.info("OAuth2User: " + oAuth2User.getAttributes());

        Optional<UserEntity> optionalUser = userRepository.findByEmail(oAuth2User.getAttribute("email"));
        UserEntity userEntity;
        if (optionalUser.isEmpty()) {
            userEntity = generateUserDtoByProvider(userRequest, oAuth2User);
            userRepository.save(userEntity);
        } else {
            userEntity = optionalUser.get();
        }

        return new UserDetailsImpl(UserDto.toDto(userEntity), oAuth2User.getAttributes());
    }

    private UserEntity generateUserDtoByProvider(OAuth2UserRequest userRequest, OAuth2User oAuth2User) {
        String providerIdentifier = userRequest.getClientRegistration().getRegistrationId();
        OAuthUserInfoMaker oAuthUserInfoMaker =
                oAuthUserInfoMakerMap.get(OAuth2Provider.getProvider(providerIdentifier));
        OAuthUserInfo oAuthUserInfo = oAuthUserInfoMaker.makeUserInfo(oAuth2User);
        return UserEntity.builder()
                .email(oAuthUserInfo.getUserEmail())
                .password(passwordEncoder.encode(oAuthUserInfo.getUserPasswordNotEncoded() + "_myApp"))
                .role(oAuthUserInfo.getUserRole())
                .oAuth2Provider(oAuthUserInfo.getOAuth2Provider())
                .build();
    }
}