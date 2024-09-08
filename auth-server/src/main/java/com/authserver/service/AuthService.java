package com.authserver.service;

import com.authserver.dto.AccountInfoResponse;
import com.authserver.repository.AccountRepository;
import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Transactional
@Service
public class AuthService {

    private final AccountRepository accountRepository;


    public AccountInfoResponse getInfo(String userId) {
        return accountRepository.findAccountInfoByUserId("wjdgns@naver.com")
                .orElseThrow(() -> new GlobalException(ResponseCode.NOT_FOUND_ACCOUNT));
    }

}
