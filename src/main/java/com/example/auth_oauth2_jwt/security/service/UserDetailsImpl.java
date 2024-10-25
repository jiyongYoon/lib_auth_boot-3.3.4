package com.example.auth_oauth2_jwt.security.service;

import com.example.auth_oauth2_jwt.dto.UserDto;
import lombok.ToString;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * @UserDetails 일반 회원가입 및 로그인 시 만들어지는 객체
 * @OAuth2User OAuth 회원가입 및 로그인 시 만들어지는 객체
 * @UserDetailsImpl 두 객체를 모두 구현하여 App 내에서는 해당 객체를 사용
 */
@ToString
public class UserDetailsImpl implements OAuth2User, UserDetails {

    private UserDto userDto;
    private Map<String, Object> attributes; // oauth2 로그인시 정보 담는 곳

    // 일반로그인
    public UserDetailsImpl(UserDto userDto) {

        this.userDto = userDto;
    }

    public UserDto getUserDto() {
        return this.userDto;
    }

    // OAuth 로그인
    public UserDetailsImpl(UserDto userDto, Map<String, Object> attributes) {

        this.userDto = userDto;
        this.attributes = attributes;
    }

    @Override
    public Map<String, Object> getAttributes() {

        return attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Collection<GrantedAuthority> grantedAuthorityCollection = new ArrayList<>();

        grantedAuthorityCollection.add(new GrantedAuthority() {

            @Override
            public String getAuthority() {

                return userDto.getRole();
            }
        });

        return grantedAuthorityCollection;
    }

    @Override
    public String getPassword() {
        return userDto.getPassword();
    }


    @Override
    public String getName() {
        // app login
        if (attributes == null) {
            return userDto.getUsername();
        }
        // oauth2 login
        else {
            return String.valueOf(attributes.get("name"));
        }
    }

    // email을 username으로 사용중
    public String getUsername() {

        return userDto.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return UserDetails.super.isAccountNonLocked();
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return UserDetails.super.isCredentialsNonExpired();
    }

    @Override
    public boolean isEnabled() {
        return UserDetails.super.isEnabled();
    }
}