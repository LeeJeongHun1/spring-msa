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

    @Operation(summary = "로그인", description = "로그인을 요청한다.")
    @ApiResponse(responseCode = "200", content = @Content())
    @PostMapping("/login")
    public ResponseEntity<GlobalBody<TokenResponse>> login(@RequestBody @Valid LoginRequest request) {
        return ResponseEntity.ok(GlobalBody.successWithData(authService.login(request)));
    }


    @Operation(summary = "회원가입", description = "회원가입을 요청한다.")
    @ApiResponse(responseCode = "200", content = @Content())
    @PostMapping("/join")
    public ResponseEntity<GlobalBody<Void>> join(
            @RequestBody @Valid JoinRequest request
    ) {
        authService.join(request);
        return ResponseEntity.ok(GlobalBody.success());
    }

    @Operation(summary = "인증된 사용자 API", description = "인증된 사용자만 호출 가능하다.")
    @ApiResponse(responseCode = "200", content = @Content())
    @PostMapping("/authenticated")
    public ResponseEntity<GlobalBody<Void>> authenticated() {
        return ResponseEntity.ok(GlobalBody.success());
    }

}
