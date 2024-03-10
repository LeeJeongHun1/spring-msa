package com.apigateway.filter;

import lombok.extern.slf4j.Slf4j;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;


@Slf4j
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final String ANONYMOUS = "ANONYMOUS_USER"; // token 이 없는 경우
    private final String GUEST = "GUEST_USER"; // token 은 있지만 redis 와 다를 경우 (권한 그룹이 수정되었거나 없는 경우)
//    private final String GUEST = "ANONYMOUS_USER";  // 회원가입은 했지만 권한그룹이 없는 유저
    private final String ANONYMOUS_SERVICE_TYPE = "ALL";

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
//            final String token = getAuthHeader(request);
            log.info("uri: {}", request.getURI());
//            if (StringUtils.hasText(token)) {
//                String storedToken = redisService.getAccessToken(token).block();
//
//                if (storedToken != null && storedToken.equals(token)) {
//                    this.populateRequestWithHeaders(exchange, token);
//                } else {
//                    redisService.deleteToken(token).block();
//                    // 권한 그룹 변경시 기존 유저들의 토큰이 만료된 경우 Guest 처리가 되어야 함
//                    this.populateHeaderWithGuest(exchange);
//                }
//            } else {
//                this.populateHeaderWithAnonymous(exchange);
//            }
            return chain.filter(exchange).then(
                    Mono.fromRunnable(exchange::getResponse)
            );
        };
    }

    private String getAuthHeader(ServerHttpRequest request) {
        if (hasAuthorization(request)) {
            String authorization = request.getHeaders().getOrEmpty(HttpHeaders.AUTHORIZATION).get(0);
            return removeBearer(authorization);
        }
        return null;
    }

    private boolean hasAuthorization(ServerHttpRequest request) {
        return request.getHeaders().containsKey(HttpHeaders.AUTHORIZATION);
    }


    private String removeBearer(String token) {
        String bearer = "Bearer ";
        if (token.startsWith(bearer))
            return token.replace(bearer, "");

        return token;
    }

    public static class Config {

    }
}
