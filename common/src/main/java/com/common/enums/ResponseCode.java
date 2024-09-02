package com.common.enums;

import lombok.Getter;
import org.springframework.http.HttpStatus;

import java.util.HashMap;
import java.util.Map;

@Getter
public enum ResponseCode {
    OK(200, "success", HttpStatus.OK.value()),

    /** [ -1 ~ -20 ] : INVALID_REQUEST **/
    TOKEN_INVALID_REQUEST(-1, "유효하지 않는 TOKEN 입니다. 로그인을 다시 시도하세요.", HttpStatus.UNAUTHORIZED.value()),
    TOKEN_NOT_FOUND(-2, "토큰을 찾을 수 없습니다.", HttpStatus.BAD_REQUEST.value()),
    TOKEN_EXPIRED(-3, "이미 만료된 토큰입니다.", HttpStatus.UNAUTHORIZED.value()),
    NOT_EXIST_AUTHORIZATION_HEADER(-4, "인증 헤더 정보가 존재하지 않습니다.", HttpStatus.BAD_REQUEST.value()),
    REQUIRED_PARAMETER(-5, "필수 파라미터가 없습니다.", HttpStatus.BAD_REQUEST.value()),
    REMOTE_NOT_FOUND(-6, "외부 서비스를 확인해주세요.", HttpStatus.BAD_REQUEST.value()),
    NOT_EXIST_REFRESH_TOKEN_COOKIE(-7, "refreshToken 정보가 쿠키에 존재하지않습니다.", HttpStatus.UNAUTHORIZED.value()),
    NOT_EXIST_SET_COOKIE(-8, "쿠키에 존재하지 않습니다.", HttpStatus.UNAUTHORIZED.value()),
    ACCOUNT_ACCESS_DENIED(-9, "접근권한이 없습니다.", HttpStatus.FORBIDDEN.value()),

    /** [ -110 ~ -200 ] : AUTH_SERVICE_ERROR **/
    USER_ID_DUPLICATED(-110, "유저 아이디가 중복 되었습니다.", HttpStatus.INTERNAL_SERVER_ERROR.value()),
    EXIST_EMAIL(-111, "이미 존재하는 이메일입니다.", HttpStatus.CONFLICT.value()),
    NOT_FOUND_ACCOUNT(-112, "계정 정보를 찾을 수 없습니다.", HttpStatus.NOT_FOUND.value()),
    INVALID_PASSWORD(-113, "유효하지 않은 패스워드 입니다.", HttpStatus.CONFLICT.value()),
    INVALID_PARAMETERS(-112, "유효하지 않은 인자 값 입니다.", HttpStatus.BAD_REQUEST.value()),
    RESULT_NOT_FOUND(-114, "결과가 없습니다.", HttpStatus.NOT_FOUND.value()),
    NOT_SUPPORTED_SOCIAL(-115, "지원하지 않은 소셜 서비스입니다.", HttpStatus.CONFLICT.value()),
    EXIST_ANOTHER_SOCIAL(-116, "다른 소셜 서비스로 가입된 이력이 존재합니다.", HttpStatus.CONFLICT.value()),


    /** [ -910 ~ -999 ] : EXTERNAL_ERROR **/
    NOT_PARSING_SWAGGER(-910, "Swagger Parsing Error.", HttpStatus.INTERNAL_SERVER_ERROR.value()),
    ENUM_NOT_FOUND(-911, "Enum Not Found", HttpStatus.INTERNAL_SERVER_ERROR.value()),
    UNKNOWN(-999, "알수 없는 오류입니다.", HttpStatus.INTERNAL_SERVER_ERROR.value());


    private final int status;
    private final String message;
    private final int httpStatus;

    ResponseCode(int status, String message, int httpStatus) {
        this.status = status;
        this.message = message;
        this.httpStatus = httpStatus;
    }

    private static final Map<Integer, ResponseCode> BY_STATUS = new HashMap<>();

    static {
        for (ResponseCode e: values()) {
            BY_STATUS.put(e.status, e);
        }
    }

    public static ResponseCode ofStatus(int status) {
        return BY_STATUS.get(status);
    }
}
