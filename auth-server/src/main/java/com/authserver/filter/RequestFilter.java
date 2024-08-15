package com.authserver.filter;

import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@Component
public class RequestFilter extends OncePerRequestFilter {

    @Override
    protected void doFilterInternal(
            HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        try {
            log.info(request.getRequestURI());
            log.info(request.getHeader("SERVICE_TYPE"));

        } catch (Exception e) {
            throw new GlobalException(ResponseCode.ACCOUNT_ACCESS_DENIED);
        }
        filterChain.doFilter(request, response);


    }
}
