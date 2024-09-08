package com.authserver.config.exception;

import com.common.config.exception.GlobalException;
import com.common.config.exception.GlobalExceptionHandler;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class ExceptionHandler extends GlobalExceptionHandler {
}
