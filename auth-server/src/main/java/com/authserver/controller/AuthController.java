package com.authserver.controller;

import com.authserver.dto.JoinRequest;
import com.authserver.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RequiredArgsConstructor
@RestController
@RequestMapping("/")
public class AuthController {

    private final AuthService authService;

    @GetMapping
    public ResponseEntity<String> home() {
        JoinRequest request = JoinRequest.builder()
                .userId("test@gmail.com")
                .name("아무개")
                .password("q1w2e3!@")
                .build();
        authService.join(request);
        return ResponseEntity.ok("auth service");
    }
}
