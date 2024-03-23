package com.authserver.security;

import com.common.domain.PrincipalDetails;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.dvcs.ServiceType;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class TokenProvider implements InitializingBean {

    private final String accessSecret;
    private final String refreshSecret;
    @Getter
    private final long accessTokenValidityInMilliseconds;
    @Getter
    private final long refreshTokenValidityInMilliseconds;
    long confirmTokenValidityInMilliseconds = 1000 * 60 * 10; // 10분


    private Key accessKey;
    private Key refreshKey;
    private Key confirmKey;

    public TokenProvider(
//            @Value("${jwt.access-secret}") String accessSecret,
//            @Value("${jwt.refresh-secret}") String refreshSecret,
//            @Value("${jwt.access-token-validity-in-seconds}") long accessTokenValidityInSeconds,
//            @Value("${jwt.refresh-token-validity-in-seconds}") long refreshTokenValidityInSeconds
    ) {
        this.accessSecret = "d";
        this.refreshSecret = "d";
        this.accessTokenValidityInMilliseconds = 1000;
        this.refreshTokenValidityInMilliseconds = 1000;
    }

    @Override
    public void afterPropertiesSet() {
//        this.accessKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(accessSecret));
//        this.refreshKey = Keys.hmacShaKeyFor(Decoders.BASE64.decode(refreshSecret));
    }

    public String createAccessToken(Authentication authentication) {
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
//        PayloadDto payloadDto = PayloadDto.of(
//                principalDetails.getServiceType(),
//                principalDetails.getUserId(),
//                principalDetails.getName(),
//                principalDetails.getDepartment(),
//                principalDetails.getAccountId(),
//                principalDetails.getHospitalId(),
//                authentication.getAuthorities().stream()
//                        .map(GrantedAuthority::getAuthority).collect(Collectors.toList()));
        PayloadDto payloadDto = PayloadDto.of(
                principalDetails.getUserId(),
                principalDetails.getRoles()
        );
        long now = (new Date()).getTime();
        Date validity = new Date(now + this.accessTokenValidityInMilliseconds);

        return createToken(authentication.getName(), payloadDto, validity, this.accessKey);
    }

    public String createRefreshToken(Authentication authentication) {
        String role = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        PayloadDto payloadDto = PayloadDto.of(
                principalDetails.getUserId(),
                principalDetails.getRoles()
        );

        long now = (new Date()).getTime();
        Date validity = new Date(now + this.refreshTokenValidityInMilliseconds);

        return createToken(authentication.getName(), payloadDto, validity, this.refreshKey);
    }


    private String createToken(String userId, PayloadDto payload, Date validity, Key signKey) {
        return Jwts.builder()
                .setClaims(payload.toMap())
                .setSubject(userId)
                .signWith(signKey, SignatureAlgorithm.HS512)
                .setExpiration(validity)
                .compact();
    }

    public Authentication getAuthentication(String token) {
        Claims claims = Jwts
                .parserBuilder()
                .setSigningKey(accessKey)
                .build()
                .parseClaimsJws(token)
                .getBody();

        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("role").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        User principal = new User(claims.getSubject(), "", authorities);

        return new UsernamePasswordAuthenticationToken(principal, token, authorities);
    }

    public String getUserIdFromJwtToken(String jwt) {
        return Jwts.parserBuilder().setSigningKey(this.accessKey).build().parseClaimsJws(jwt).getBody().getSubject();
    }

    public String getUserIdFromJwtConfirmToken(String jwt) {
        return Jwts.parserBuilder().setSigningKey(this.confirmKey).build().parseClaimsJws(jwt).getBody().getSubject();
    }

    public String getHospitalIdFromJwtConfirmToken(String jwt) {
        return Jwts.parserBuilder().setSigningKey(this.confirmKey).build().parseClaimsJws(jwt).getBody().get("hospitalId", String.class);
    }

    public Claims getClaimsFromJwtToken(String jwt) {
        if (validateToken(this.accessKey, jwt)) return Jwts.parserBuilder().setSigningKey(this.accessKey).build().parseClaimsJws(jwt).getBody();
        return null;
    }

    public String getHospitalIdFromJwtToken(String jwt) {
        return Jwts.parser().setSigningKey(this.accessKey).parseClaimsJws(jwt).getBody().get("hospitalId", String.class);
    }

    public String getAccountIdFromJwtToken(String jwt) {
        return Jwts.parser().setSigningKey(this.accessKey).parseClaimsJws(jwt).getBody().get("accountId", String.class);
    }

    public boolean validateAccessToken(String token) {
        return validateToken(this.accessKey, token);
    }

    //TODO validateAccessToken, validateRefreshToken 차이점 없으면 리팩토링
    public boolean validateRefreshToken(String token) {
        return validateToken(this.refreshKey, token);
    }
    public boolean validateConfirmToken(String token) {
        return validateToken(this.confirmKey, token);
    }

    private boolean validateToken(Key key, String token) {
        return false;
//        try {
//            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
//            return true;
//        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
//            log.info("잘못된 JWT 서명입니다.");
//            throw new GlobalException(ResponseCode.TOKEN_INVALID_REQUEST);
//        } catch (ExpiredJwtException e) {
//            log.info("만료된 JWT 토큰입니다.");
//            throw new GlobalException(ResponseCode.TOKEN_EXPIRED);
//        } catch (UnsupportedJwtException e) {
//            log.info("지원되지 않는 JWT 토큰입니다.");
//            throw new GlobalException(ResponseCode.TOKEN_INVALID_REQUEST);
//        } catch (IllegalArgumentException e) {
//            log.info("JWT 토큰이 잘못되었습니다.");
//            throw new GlobalException(ResponseCode.TOKEN_INVALID_REQUEST);
//        }
    }

    @Builder
    @NoArgsConstructor
    @AllArgsConstructor
    static class PayloadDto{
        private String userId;
        private List<String> role;
        public Map<String, Object> toMap(){
            Map<String, Object> map = new HashMap<>();
            map.put("userId", this.userId);
            map.put("role", this.role);

            return map;
        }

        public static PayloadDto of(String userId,
                                    List<String> role){
            return PayloadDto.builder()
                    .userId(userId)
                    .role(role)
                    .build();
        }

    }
}
