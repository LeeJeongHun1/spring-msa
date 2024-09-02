package com.authserver.service;

import com.authserver.security.TokenProvider;
import com.authserver.dto.JoinRequest;
import com.authserver.dto.LoginRequest;
import com.authserver.dto.TokenResponse;
import com.authserver.entity.Account;
import com.authserver.repository.AccountRepository;
import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Transactional
@Service
public class AuthService {

    private final AccountRepository accountRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenProvider tokenProvider;


}
