package com.authserver.componet;

import com.authserver.entity.Account;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;

@Component
public class TokenProvider {

    private final String accessSecret;
    private final String refreshSecret;

    private final long accessTokenValidityInMilliseconds;
    private final long refreshTokenValidityInMilliseconds;
    private Key accessKey;
    private Key refreshKey;

    public TokenProvider(
            @Value("${jwt.access-secret}") String accessSecret,
            @Value("${jwt.refresh-secret}") String refreshSecret,
            @Value("${jwt.access-token-validity-in-seconds}") long accessTokenValidityInMilliseconds,
            @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInMilliseconds
    ) {
        this.accessSecret = accessSecret;
        this.refreshSecret = refreshSecret;
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMilliseconds;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMilliseconds;
        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessSecret));
        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecret));
    }

    public void createAccessToken(Account account) {
        long now = new Date().getTime();
        Date expireDate = new Date(now + accessTokenValidityInMilliseconds);
        createToken(account.getUserId(), expireDate, accessKey);
    }


    private String createToken(String userId, Date validity, Key signKey) {
        return Jwts.builder()
                .setSubject(userId)
                .signWith(signKey, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

}
