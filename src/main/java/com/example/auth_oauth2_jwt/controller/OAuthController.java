package com.example.auth_oauth2_jwt.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
public class OAuthController {

    @GetMapping("/oauth/login")
    public String oauthLogin() {
        System.out.println("oauth login");
        return "oauth-login";
    }

    @GetMapping("/api/oauth-jwt")
    @ResponseBody
    public String jwtResponse() {
        System.out.println("jwt response!");
        return "jwt response!";
    }

}