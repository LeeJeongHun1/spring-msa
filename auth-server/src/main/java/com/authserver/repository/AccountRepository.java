package com.authserver.repository;

import com.authserver.entity.Account;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AccountRepository extends JpaRepository<Account, Long>, AccountCustomRepository {

    Optional<Account> findByUserId(String userId);
}
