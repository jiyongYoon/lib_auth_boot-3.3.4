package com.example.auth_oauth2_jwt.security.service;

import com.example.auth_oauth2_jwt.dto.UserDto;
import com.example.auth_oauth2_jwt.entity.UserEntity;
import com.example.auth_oauth2_jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String userEmail) throws UsernameNotFoundException {
        UserEntity findUser = userRepository.findByEmail(userEmail).orElseThrow();
        return new UserDetailsImpl(UserDto.toDto(findUser));
    }
}