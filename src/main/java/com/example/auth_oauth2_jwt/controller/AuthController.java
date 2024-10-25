package com.example.auth_oauth2_jwt.controller;

import com.example.auth_oauth2_jwt.security.service.UserDetailsImpl;
import com.example.auth_oauth2_jwt.dto.UserDto;
import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import com.example.auth_oauth2_jwt.service.UserService;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class AuthController {

    private final UserService userService;
    private final RefreshTokenStorage refreshTokenStorage;

    @PostMapping("/signup")
    public UserDto createUser(@RequestBody UserDto userDto) {
        return userService.createUser(userDto);
    }

    // 저장된 리프레시 토큰 확인용
    @GetMapping("/token")
    public Map<String, String> getSavedToken() {
        return refreshTokenStorage.getInstance();
    }

    // 시큐리티 컨텍스트 확인용
    @GetMapping("/context")
    public String getSecurityContext(
        @AuthenticationPrincipal UserDetailsImpl userDetails,
        HttpServletRequest request
    ) {
        Cookie[] cookies = request.getCookies();
        for (Cookie cookie : cookies) {
            System.out.println("security context from cookie: " + cookie.getName() + " / " + cookie.getValue());
        }
        return userDetails.getUserDto().toString();
    }

}