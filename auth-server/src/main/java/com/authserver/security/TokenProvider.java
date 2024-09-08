package com.authserver.security;

import com.authserver.dto.TokenResponse;
import com.authserver.entity.Account;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
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
        this.accessTokenValidityInMilliseconds = accessTokenValidityInMilliseconds * 1000;
        this.refreshTokenValidityInMilliseconds = refreshTokenValidityInMilliseconds * 1000;
        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessSecret));
        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecret));
    }

    public TokenResponse createAccessTokenWithRefreshToken(String email) {
        return TokenResponse.builder()
                .accessToken(createAccessToken(email, accessKey))
                .refreshToken(createRefreshToken(email, refreshKey))
                .build();
    }


    private String createAccessToken(String email, Key signKey) {
        long now = new Date().getTime();
        Date expireDate = new Date(now + accessTokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(email)
                .signWith(signKey, SignatureAlgorithm.HS512)
                .setExpiration(expireDate)
                .compact();
    }

    private String createRefreshToken(String email, Key signKey) {
        long now = new Date().getTime();
        Date expireDate = new Date(now + refreshTokenValidityInMilliseconds);

        return Jwts.builder()
                .setSubject(email)
                .signWith(signKey, SignatureAlgorithm.HS512)
                .setExpiration(expireDate)
                .compact();
    }

}
