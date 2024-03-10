package com.authserver.security;

import com.beplushealthcare.auth.config.security.jwt.JwtAccessDeniedHandler;
import com.beplushealthcare.auth.config.security.jwt.JwtAuthenticationEntryPoint;
import com.beplushealthcare.auth.support.GatewayRequestFilter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Slf4j
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {


//    private final GatewayRequestFilter gatewayRequestFilter;
//    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;
//    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
//        http
//                .addFilterBefore(gatewayRequestFilter, UsernamePasswordAuthenticationFilter.class)
//                .exceptionHandling(exceptionHandler -> exceptionHandler.authenticationEntryPoint(jwtAuthenticationEntryPoint))
//                .exceptionHandling(exceptionHandler -> exceptionHandler.accessDeniedHandler(jwtAccessDeniedHandler));

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .sessionManagement(configurer -> configurer.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests((t) -> t
                        .requestMatchers(HttpMethod.POST, "/api/v1/backoffice/accounts/sign-in").permitAll() // 로그인
                        .requestMatchers("/api/v1/backoffice/accounts/password").permitAll() // 패스워드 변경
                        .requestMatchers("/api/v1/backoffice/accounts/token-refresh").permitAll() // 토큰 재발급
                        .requestMatchers("/api/v1/backoffice/accounts/verify-confirm-token").permitAll() // 토큰 재발급
                        .requestMatchers("/api/v1/hospital/accounts/token-refresh").permitAll() // 토큰 재발급
                        .requestMatchers("/api/v1/common/nice/**").permitAll() // nice
                        // 병원 로그인
                        .requestMatchers("/api/v1/hospital/accounts/verify-reCaptcha").permitAll() // google captcha
                        .requestMatchers(HttpMethod.POST, "/api/v1/hospital/accounts/sign-in/**").permitAll()
                        .requestMatchers("/auth/swagger-ui/**",
                                        "/v3/api-docs/**").permitAll() // swagger
                        // 백오피스, 병원 비밀번호 변경 요청, 연락처 재설정
                        .requestMatchers("/api/v1/*/accounts/user-ids/*/*-reset/send-email").permitAll()
                        .requestMatchers("/api/v1/*/accounts/password-reset/**").permitAll()
                        .requestMatchers("/api/v1/*/accounts/phone-number").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/v1/hospital/accounts/check").permitAll() // 병원 : 토큰 체크
                        .requestMatchers(HttpMethod.POST, "/api/v1/hospital/accounts").permitAll() // 병원 : 토큰을 통한 가입
                        .anyRequest().authenticated());
        return http.build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(Arrays.asList("http://127.0.0.1", "*", "http://localhost:3000", "http://localhost:5173", "https://firstchart.whatailsyou.io/"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PUT","DELETE","PATCH","OPTIONS"));
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Authorization-refresh", "Cache-Control", "Content-Type"));
        configuration.setExposedHeaders(Arrays.asList("Authorization", "Authorization-refresh", "Set-Cookie"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // 공식 문서
    // https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html
    @Bean
    @Role(BeanDefinition.ROLE_INFRASTRUCTURE)
    static Advisor preAuthorizeMethodInterceptor() {
        return AuthorizationManagerBeforeMethodInterceptor.preAuthorize();
    }
}
