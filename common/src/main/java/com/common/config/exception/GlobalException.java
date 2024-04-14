package com.common.config.exception;

import com.common.enums.ResponseCode;
import lombok.Data;
import lombok.EqualsAndHashCode;
import org.springframework.http.HttpStatus;

@Data
@EqualsAndHashCode(callSuper = false)
public class GlobalException extends RuntimeException {

    private int errorCode;
    private Object data;
    private int httpStatus;

    public GlobalException() {
        super();
    }

    public GlobalException(String message, int errorCode, Throwable cause) {
        super(message, cause);
        this.errorCode = errorCode;
    }

    public GlobalException(String message, Throwable cause) {
        super(message, cause);
        this.errorCode = -999;
    }

    public GlobalException(String message, int errorCode) {
        super(message);
        this.errorCode = errorCode;
    }

    public GlobalException(String message) {
        super(message);
        this.errorCode = -999;
    }

    public GlobalException(ResponseCode responseCode) {
        super(responseCode.getMessage());
        this.errorCode = responseCode.getStatus();
        this.httpStatus = responseCode.getHttpStatus();
    }
//
//    public GlobalException(ResponseCode responseCode, Object data) {
//        super(responseCode.getMessage());
//        this.errorCode = responseCode.getStatus();
//        this.httpStatus = responseCode.getHttpStatus();
//        this.data = data;
//    }
//
//    public GlobalException(String message, ResponseCode responseCode) {
//        super(message);
//        this.errorCode = responseCode.getStatus();
//        this.httpStatus = responseCode.getHttpStatus();
//    }
//
//    public GlobalException(String message, ResponseCode responseCode, Object data) {
//        super(message);
//        this.errorCode = responseCode.getStatus();
//        this.httpStatus = responseCode.getHttpStatus();
//        this.data = data;
//    }

    public GlobalException(HttpStatus status, String message){
        super(message);
        this.errorCode = status.value();
        this.httpStatus = status.value();
    }

    public GlobalException(Throwable cause) {
        super(cause);
    }

    public static class NotFoundException extends GlobalException {

    }

}