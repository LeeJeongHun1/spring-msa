package com.common.config.exception;

import org.springframework.http.HttpStatus;

public class NotFoundException extends GlobalException{
    public NotFoundException(String errorCode) {
        super(HttpStatus.NOT_FOUND, errorCode);
    }
}
