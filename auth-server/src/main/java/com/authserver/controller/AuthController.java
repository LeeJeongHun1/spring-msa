package com.authserver.controller;

import com.authserver.dto.AccountInfoResponse;
import com.authserver.dto.JoinRequest;
import com.authserver.dto.LoginRequest;
import com.authserver.dto.TokenResponse;
import com.authserver.service.AuthService;
import com.common.domain.GlobalBody;
import com.common.domain.PrincipalDetails;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@Tag(name = "인증 API", description = "인증 서비스")
@RestController
@RequestMapping("/api/v1/")
public class AuthController {

    private final AuthService authService;


    @Operation(summary = "내 정보 확인", description = "내 계정의 정보를 요청한다.")
    @ApiResponse(responseCode = "200", content = @Content(schema = @Schema(implementation = AccountInfoResponse.class)))
    @GetMapping("/me")
    public ResponseEntity<GlobalBody<AccountInfoResponse>> get(
            @AuthenticationPrincipal PrincipalDetails principalDetails
    ) {
        return ResponseEntity.ok(GlobalBody.successWithData(authService.getInfo(principalDetails.getUserId())));
    }
}
