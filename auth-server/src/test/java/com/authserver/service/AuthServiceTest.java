package com.authserver.service;

import com.authserver.dto.JoinRequest;
import com.authserver.entity.Account;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockingDetails;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockingDetails;

@SpringBootTest
@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Autowired
    AuthService authService;

    @Test
    void join() {
        Account mock = mock(Account.class);
        JoinRequest request = JoinRequest.builder()
                .userId("test@gmail.com")
                .name("아무개")
                .password("q1w2e3!@")
                .build();

        authService.join(request);
    }
}