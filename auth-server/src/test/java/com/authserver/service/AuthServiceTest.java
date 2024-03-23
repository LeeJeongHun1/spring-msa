package com.authserver.service;

import com.authserver.dto.JoinRequest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
class AuthServiceTest {

    @Autowired
    AuthService authService;

    @Test
    void join() {
        JoinRequest request = JoinRequest.builder()
                .userId("test@gmail.com")
                .name("아무개")
                .password("q1w2e3!@")
                .build();

        authService.join(request);
    }
}