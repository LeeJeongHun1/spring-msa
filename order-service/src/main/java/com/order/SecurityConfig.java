package com.order;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.aop.Advisor;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
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
                        .anyRequest().permitAll());
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
