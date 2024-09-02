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
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@Tag(name = "인증 API", description = "인증 서비스")
@RestController
@RequestMapping("/api/v1/")
public class AuthController {

    private final AuthService authService;

}
