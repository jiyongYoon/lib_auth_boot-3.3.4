package com.example.auth_oauth2_jwt.security.oauth;

import com.example.auth_oauth2_jwt.security.jwt.util.CookieGenerator;
import com.example.auth_oauth2_jwt.security.service.UserDetailsImpl;
import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import com.example.auth_oauth2_jwt.security.jwt.dto.GenerateJwtRequest;
import com.example.auth_oauth2_jwt.security.jwt.util.JwtGenerator;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;

@Slf4j
@RequiredArgsConstructor
public class OAuth2MemberSuccessHandler implements AuthenticationSuccessHandler {

    private final RefreshTokenStorage refreshTokenStorage;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        log.info("oauth2 user login success!! username={}", authentication);
        UserDetailsImpl authenticateUserDetails = (UserDetailsImpl) authentication.getPrincipal();

        String accessToken = JwtGenerator.generateAccessToken(GenerateJwtRequest.builder()
            .userId(authenticateUserDetails.getUserDto().getId())
            .userEmail(authenticateUserDetails.getUsername())
            .userRole(authenticateUserDetails.getUserDto().getRole())
            .build());
        String refreshToken = JwtGenerator.generateRefreshToken();

        refreshTokenStorage.saveAccessAndRefreshToken(accessToken, refreshToken);

        // 여기서 Header에 담을지, Cookie에 담을지
        response.addCookie(CookieGenerator.create(HttpHeaders.AUTHORIZATION, accessToken));
        response.sendRedirect("http://localhost:8080/api/context");
//        response.sendRedirect(createURI(
//            accessToken,
//            refreshToken,
//            authenticateUserDetails.getUserDto().getId(),
//            authenticateUserDetails.getUserDto().getEmail()).toString());
    }

    private URI createURI(String accessToken, String refreshToken, Long userId, String username) {
        MultiValueMap<String, String> queryParams = new LinkedMultiValueMap<>();
        queryParams.add("user_id", String.valueOf(userId));
        queryParams.add("user_name", username);
        queryParams.add("access_token", accessToken);
        queryParams.add("refresh_token", refreshToken);

        return UriComponentsBuilder
            .newInstance()
            .scheme("http")
//            .host("localhost:8080")
            .path("/api/oauth-jwt")
            .queryParams(queryParams)
            .build()
            .toUri();
    }
}
