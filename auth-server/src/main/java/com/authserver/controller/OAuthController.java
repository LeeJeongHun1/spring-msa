package com.authserver.controller;

import com.authserver.dto.JoinRequest;
import com.authserver.dto.LoginRequest;
import com.authserver.dto.TokenResponse;
import com.authserver.service.AuthService;
import com.common.domain.GlobalBody;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

@RequiredArgsConstructor
@Tag(name = "oAuth API", description = "oAuth 서비스")
@Controller
//@RequestMapping("/api/v1/")
public class OAuthController {

    @Value("${spring.security.oauth2.client.provider.naver.authorization_uri}")
    private String url;
    @Value("${spring.security.oauth2.client.registration.naver.client-id}")
    private String clientId;
    @Value("${spring.security.oauth2.client.registration.naver.redirect-uri}")
    private String redirectUrl;


    @Operation(summary = "로그인", description = "로그인을 요청한다.")
    @ApiResponse(responseCode = "200", content = @Content())
    @RequestMapping("/oAuth-login")
    public String login(Model model, HttpServletRequest request) throws UnsupportedEncodingException {
        SecureRandom random = new SecureRandom();
        String state = new BigInteger(130, random).toString();
        String url = String.format("%s?response_type=code&client_id=%s&redirect_uri=%s&state=%s", this.url, clientId, URLEncoder.encode(redirectUrl, StandardCharsets.UTF_8), state);
        request.getSession().setAttribute("state", state);
        model.addAttribute("url", url);
        return "login";
    }

//    @ApiResponse(responseCode = "200", content = @Content())
//    @RequestMapping("/login/oauth2/code/naver")
//    public String callBack() {
//        return "callBack";
//    }


}
