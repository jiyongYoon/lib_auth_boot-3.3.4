package com.example.auth_oauth2_jwt.security.filter;

import com.example.auth_oauth2_jwt.security.jwt.util.CookieGenerator;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;

@Slf4j
public class OAuth2LoginTokenResponseFilter implements Filter {

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
        throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        if (httpRequest.getRequestURI().startsWith("/api/oauth-jwt")) {
            log.info("oauth-jwt redirect!");
            String accessToken = request.getParameter("access_token");
            String refreshToken = request.getParameter("refresh_token");

//            httpResponse.addHeader(HttpHeaders.AUTHORIZATION, TOKEN_PREFIX + accessToken);
//            httpResponse.addHeader(JwtProperties.REFRESH_TOKEN_HEADER, refreshToken);

            httpResponse.addCookie(CookieGenerator.create(HttpHeaders.AUTHORIZATION, accessToken));
            httpResponse.sendRedirect("http://localhost:8080/api/context");
        }

        chain.doFilter(request, response);
    }
}
