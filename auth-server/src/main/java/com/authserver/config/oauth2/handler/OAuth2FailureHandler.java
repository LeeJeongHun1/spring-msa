package com.authserver.config.oauth2.handler;

import com.authserver.security.TokenProvider;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@RequiredArgsConstructor
@Component
public class OAuth2FailureHandler implements AuthenticationFailureHandler {

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {

        response.sendRedirect("/fail");
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