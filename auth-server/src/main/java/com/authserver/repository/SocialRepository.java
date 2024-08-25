package com.authserver.repository;

import com.authserver.entity.Account;
import com.authserver.entity.Social;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface SocialRepository extends JpaRepository<Social, String> {

}
