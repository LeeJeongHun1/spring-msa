package com.authserver.repository;

import com.authserver.dto.AccountInfoResponse;

import java.util.Optional;

public interface AccountCustomRepository {

    Optional<AccountInfoResponse> findAccountInfoByUserId(String userId);
}
