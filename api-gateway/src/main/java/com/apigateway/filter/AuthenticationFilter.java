package com.apigateway.filter;

import com.apigateway.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;


@Slf4j
@Component
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    private final String ANONYMOUS = "ANONYMOUS_USER"; // token 이 없는 경우
    private final String USER_SERVICE_TYPE = "USER";
    private final String ADMIN_SERVICE_TYPE = "ADMIN";
    @Autowired
    private JwtUtil jwtUtil;


    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            final String token = getAuthHeader(request);
            log.info("uri: {}", request.getURI());
            log.info("uri: {}", request.getPath());
            if (StringUtils.hasText(token)) {
                    this.populateRequestWithHeaders(exchange, token);
            } else {
                this.populateHeaderWithAnonymous(exchange);
            }
            return chain.filter(exchange).then(
                    Mono.fromRunnable(exchange::getResponse)
            );
        };
    }

    private void populateHeaderWithAnonymous(ServerWebExchange exchange) {
        exchange.getRequest().mutate()
                .header("SERVICE_TYPE", ANONYMOUS)
                .build();
    }

    private void populateRequestWithHeaders(ServerWebExchange exchange, String token) {
        jwtUtil.getAllClaimsFromToken(token);
        exchange.getRequest().mutate()
                .header("SERVICE_TYPE", USER_SERVICE_TYPE)
                .header("USER_ID", jwtUtil.getAccountIdFromJwtToken(token))
                .build();
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
