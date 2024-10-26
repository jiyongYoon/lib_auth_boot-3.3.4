package com.example.auth_oauth2_jwt.service;

import com.example.auth_oauth2_jwt.dto.UserDto;
import com.example.auth_oauth2_jwt.entity.UserEntity;
import com.example.auth_oauth2_jwt.entity.UserRole;
import com.example.auth_oauth2_jwt.repository.UserRepository;
import com.example.auth_oauth2_jwt.security.oauth.OAuth2Provider;
import java.util.Optional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;

    private final PasswordEncoder passwordEncoder;

    public UserDto createUser(UserDto userDto) {
        Optional<UserEntity> optionalUser = userRepository.findByEmail(userDto.getEmail());
        if (optionalUser.isPresent()) {
            log.error("already exist!! email = {}", userDto.getEmail());
            return UserDto.toDto(optionalUser.get());
        }

        UserEntity userEntity = UserEntity.builder()
                .username(userDto.getUsername())
                .email(userDto.getEmail())
                .password(passwordEncoder.encode(userDto.getPassword()))
                .role(UserRole.ROLE_USER)
                .oAuth2Provider(OAuth2Provider.APP)
                .build();

        return UserDto.toDto(userRepository.save(userEntity));
    }
}