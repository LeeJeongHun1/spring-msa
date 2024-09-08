package com.apigateway.security;

import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;

@Slf4j
@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private Key key;

    @PostConstruct
    public void init() {
        this.key = Keys.hmacShaKeyFor(Decoders.BASE64.decode(secret));
    }

    public Claims getAllClaimsFromToken(String token){
        try{
            return Jwts
                    .parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(removeBearer(token))
                    .getBody();
        } catch (SecurityException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            throw new GlobalException(ResponseCode.TOKEN_INVALID_REQUEST);
        } catch (ExpiredJwtException e) {
            throw new GlobalException(ResponseCode.TOKEN_EXPIRED);
        } catch (Exception e) {
            log.error(e.getMessage());
            throw new GlobalException(ResponseCode.TOKEN_INVALID_REQUEST);
        }
    }

    public String getAccountIdFromJwtToken(String token) {
        Claims claims = getAllClaimsFromToken(token);
        return claims.getSubject();
    }

    private String removeBearer(String token) {
        String bearer = "Bearer ";
        if (token.startsWith(bearer))
            return token.replace(bearer, "");

        return token;
    }
}
