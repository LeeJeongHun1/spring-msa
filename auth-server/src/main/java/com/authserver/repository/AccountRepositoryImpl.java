package com.authserver.repository;

import com.authserver.dto.AccountInfoResponse;
import com.authserver.entity.Account;
import com.authserver.entity.QAccount;
import com.authserver.entity.QSocial;
import com.common.support.Querydsl5RepositorySupport;

import java.util.Optional;

public class AccountRepositoryImpl extends Querydsl5RepositorySupport implements AccountCustomRepository{

    private final QAccount account = QAccount.account;
    private final QSocial social = QSocial.social;

    protected AccountRepositoryImpl() {
        super(Account.class);
    }

    @Override
    public Optional<AccountInfoResponse> findAccountInfoByUserId(String userId) {
        return Optional.ofNullable(
                getQueryFactory().select(AccountInfoResponse.create(account, social))
                        .from(account)
                        .leftJoin(social).on(social.account.eq(account))
                        .where(eq(account.userId, userId))
                        .fetchFirst()
        );
    }
}
