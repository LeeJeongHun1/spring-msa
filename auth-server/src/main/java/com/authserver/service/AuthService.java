package com.authserver.service;

import com.authserver.dto.JoinRequest;
import com.authserver.entity.Account;
import com.authserver.repository.AccountRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@RequiredArgsConstructor
@Transactional
@Service
public class AuthService {

    private final AccountRepository accountRepository;
    private final ApplicationEventPublisher applicationEventPublisher;

    public void join(JoinRequest request) {
        log.info("join start");

        Account account = Account.create(request);
//        accountRepository.save(account);
        log.info("account save");

        // send join Email
        log.info("event publish");
        applicationEventPublisher.publishEvent(request);

        log.info("join end");
    }
}
