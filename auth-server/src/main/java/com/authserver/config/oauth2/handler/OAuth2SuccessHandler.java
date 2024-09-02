package com.authserver.config.oauth2.handler;

import com.authserver.config.oauth2.OAuth2CustomUser;
import com.authserver.dto.TokenResponse;
import com.authserver.security.TokenProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class OAuth2SuccessHandler implements AuthenticationSuccessHandler {

    private final TokenProvider tokenProvider;
    private static final String URI = "/auth/success";

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // token create
        OAuth2CustomUser oAuth2CustomUser = (OAuth2CustomUser) authentication.getPrincipal();
        TokenResponse accessTokenWithRefreshToken = tokenProvider.createAccessTokenWithRefreshToken(oAuth2CustomUser.getUsername());
        response.sendRedirect(URI + "/" + accessTokenWithRefreshToken.getAccessToken());
    }


//    @Override
//    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
//                                        Authentication authentication) throws IOException, ServletException {
//        // accessToken, refreshToken 발급
//        String accessToken = tokenProvider.generateAccessToken(authentication);
//        tokenProvider.generateRefreshToken(authentication, accessToken);
//
//        // 토큰 전달을 위한 redirect
//        String redirectUrl = UriComponentsBuilder.fromUriString(URI)
//                .queryParam("accessToken", accessToken)
//                .build().toUriString();
//
//        response.sendRedirect(redirectUrl);
//    }
}