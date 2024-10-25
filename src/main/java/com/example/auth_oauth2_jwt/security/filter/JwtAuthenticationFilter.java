package com.example.auth_oauth2_jwt.security.filter;

import com.example.auth_oauth2_jwt.security.jwt.JwtLoginVo;
import com.example.auth_oauth2_jwt.security.jwt.RefreshTokenStorage;
import com.example.auth_oauth2_jwt.security.jwt.dto.GenerateJwtRequest;
import com.example.auth_oauth2_jwt.security.jwt.util.CookieGenerator;
import com.example.auth_oauth2_jwt.security.jwt.util.JwtGenerator;
import com.example.auth_oauth2_jwt.security.service.UserDetailsImpl;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;


@Slf4j
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final ObjectMapper objectMapper = new ObjectMapper();

    private final RefreshTokenStorage refreshTokenStorage;
    private final String FILTER_PROCESS_URL = "/api/login";


    public JwtAuthenticationFilter(AuthenticationManager authenticationManager, RefreshTokenStorage refreshTokenStorage) {
        super.setFilterProcessesUrl(FILTER_PROCESS_URL);
        super.setAuthenticationManager(authenticationManager);
        this.refreshTokenStorage = refreshTokenStorage;
    }

    /**
     * 인증 요청 시 실행되는 메서드
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException {
        log.info("================ JwtAuthenticationFilter ================");

        // 1. json RequestBody 에서 값 추출
//        try {
//            BufferedReader br = request.getReader();
//            String input = null;
//            while((input = br.readLine()) != null) {
//                System.out.println(input);
//            }
//        } catch (IOException e) {
//            e.printStackTrace();
//        }
        JwtLoginVo jwtLoginVo = null;
        try {
            jwtLoginVo = objectMapper.readValue(request.getInputStream(), JwtLoginVo.class);
            log.info("login request!! username={}", jwtLoginVo.getUsername());
        } catch (IOException e) {
            log.error("objectMapper.readValue() exception");
            throw new RuntimeException(e);
        }

        // 2. 시큐리티에서 사용할 인증 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
                new UsernamePasswordAuthenticationToken(jwtLoginVo.getUsername(), jwtLoginVo.getPassword());

        // 3. AuthenticationManager에게 인증 위임 -> loadUserByUsername()으로 DB에서 데이터 확인
        return super.getAuthenticationManager().authenticate(authenticationToken);
    }

    /**
     * 인증 성공 시 실행되는 메서드
     */
    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
                                            FilterChain chain, Authentication authResult) throws IOException {

        UserDetailsImpl authenticateUserDetails = (UserDetailsImpl) authResult.getPrincipal();
        log.info("login success!! username={}", authenticateUserDetails.getUsername());
        /** (Optional) Spring Security Context에 저장
         * -> 추가 학습을 해보니 WebSecurityConfig에서 sessionCreationPolicy 정책이 설정되어 있으면
         * -> loadUserByUsername 호출 시 return 값이 Context에 저장이 되어 굳이 안해줘도 됨...
         * SecurityContext context = SecurityContextHolder.createEmptyContext();
         * context.setAuthentication(authResult);
         * SecurityContextHolder.setContext(context);
         */

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
    }
}
