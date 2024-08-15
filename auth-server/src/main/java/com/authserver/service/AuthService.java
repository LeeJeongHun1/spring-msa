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

//    private final ApplicationEventPublisher applicationEventPublisher;

    public void join(JoinRequest request) {
        if (accountRepository.findByUserId(request.getUserId()).isPresent()) {
            throw new GlobalException(ResponseCode.EXIST_EMAIL);
        }

        Account account = Account.builder()
                .userId(request.getUserId())
                .name(request.getName())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        accountRepository.save(account);
    }

    public TokenResponse login(LoginRequest request) {
        Account account = accountRepository.findByUserId(request.getUserId())
                .orElseThrow(() -> new GlobalException(ResponseCode.NOT_FOUND_ACCOUNT));

        if (!passwordEncoder.matches(request.getPassword(), account.getPassword())) {
            throw new GlobalException(ResponseCode.INVALID_PASSWORD);
        }
        // token 반환.

        return tokenProvider.createAccessTokenWithRefreshToken(account);
    }
}
