package com.example.auth_oauth2_jwt.security.service;

import com.example.auth_oauth2_jwt.dto.*;
import com.example.auth_oauth2_jwt.entity.UserEntity;
import com.example.auth_oauth2_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final UserRepository userRepository;

    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {

        OAuth2User oAuth2User = super.loadUser(userRequest);

        System.out.println("OAuth2User: " + oAuth2User);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        OAuth2Response oAuth2Response = null;
        if (registrationId.equals(OAuth2Provider.NAVER.getValue())) {
            oAuth2Response = new NaverResponse(oAuth2User.getAttributes());
        } else if (registrationId.equals(OAuth2Provider.GOOGLE.getValue())) {
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        } else {
            return null;
        }

        //리소스 서버에서 발급 받은 정보로 사용자를 특정할 아이디값을 만듬
        String username = oAuth2Response.getProvider() + "_" + oAuth2Response.getProviderId();
        Optional<UserEntity> existData = userRepository.findByUsername(username);

        if (existData.isEmpty()) {

            UserEntity userEntity = new UserEntity();
            userEntity.setUsername(username);
            userEntity.setEmail(oAuth2Response.getEmail());
            userEntity.setName(oAuth2Response.getName());
            userEntity.setRole("ROLE_USER");

            userRepository.save(userEntity);

            UserDto userDto = new UserDto();
            userDto.setUsername(username);
            userDto.setName(oAuth2Response.getName());
            userDto.setRole("ROLE_USER");

            return new CustomOAuth2User(userDto);
        } else {

            UserEntity existUser = existData.get();
            existUser.setEmail(oAuth2Response.getEmail());
            existUser.setName(oAuth2Response.getName());

            userRepository.save(existUser);

            UserDto userDto = new UserDto();
            userDto.setUsername(existUser.getUsername());
            userDto.setName(oAuth2Response.getName());
            userDto.setRole(existUser.getRole());

            return new CustomOAuth2User(userDto);
        }
    }
}