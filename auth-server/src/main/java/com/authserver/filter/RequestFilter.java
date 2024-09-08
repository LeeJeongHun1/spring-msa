package com.authserver.filter;

import com.common.config.exception.GlobalException;
import com.common.domain.PrincipalDetails;
import com.common.enums.ResponseCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class RequestFilter extends OncePerRequestFilter {

    private final String ANONYMOUS = "ANONYMOUS_USER"; // token 이 없는 경우
    private final String USER_SERVICE_TYPE = "USER";

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            String userId = request.getHeader("USER_ID");
            String serviceType = request.getHeader("SERVICE_TYPE");
            if (serviceType.equals(USER_SERVICE_TYPE)) {

                PrincipalDetails principalDetails = PrincipalDetails.builder()
                        .userId(userId)
                        .build();

                Authentication authentication =
                        new UsernamePasswordAuthenticationToken(
                                principalDetails, null, principalDetails.getAuthorities());

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }


        } catch (Exception e) {
            throw new GlobalException(ResponseCode.ACCOUNT_ACCESS_DENIED);
        }
        filterChain.doFilter(request, response);


    }
}
