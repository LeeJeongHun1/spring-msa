package com.common.domain;

import com.common.config.exception.GlobalException;
import com.common.enums.ResponseCode;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.servlet.http.HttpServletRequest;
import lombok.*;
import org.springframework.data.domain.Page;
import org.springframework.web.context.request.RequestAttributes;

import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;


import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;

@Getter
@NoArgsConstructor
@ToString(doNotUseGetters = true)
public class GlobalBody<T> {

    @Schema(description = "응답코드", example = "0", requiredMode = Schema.RequiredMode.REQUIRED)
    private int status;
    @Schema(description = "데이터", example = "{}", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private T data;
    @Schema(description = "응답 메시지", example = "성공", requiredMode = Schema.RequiredMode.REQUIRED)
    private String message;
    @Schema(description = "응답 시간", example = "2023-09-19 22:01:32", requiredMode = Schema.RequiredMode.REQUIRED)
    private LocalDateTime timestamp = LocalDateTime.now();
    @Schema(description = "디버깅용 메세지", example = "", requiredMode = Schema.RequiredMode.NOT_REQUIRED)
    private String trace = "";
    @Schema(description = "요청 URL 경로", example = "2023-09-19 22:01:32", requiredMode = Schema.RequiredMode.REQUIRED)
    private String path = getRequestUri();

    @Builder
    public GlobalBody(int status, String message) {
        this.status = status;
        this.message = message;
    }

    @Builder
    public GlobalBody(int status, String message, String stackTrace) {
        this.status = status;
        this.message = message;
        this.trace = stackTrace;
    }

    @Builder
    public GlobalBody(T data, int status, String message) {
        this.data = data;
        this.status = status;
        this.message = message;
    }

    public GlobalBody(T data, ResponseCode responseCode) {
        this.data = data;
        this.status = responseCode.getStatus();
        this.message = responseCode.getMessage();
    }

    public GlobalBody(T data, ResponseCode responseCode, String message) {
        this.data = data;
        this.status = responseCode.getStatus();
        this.message = message;
    }

    public GlobalBody(ResponseCode responseCode) {
        this.status = responseCode.getStatus();
        this.message = responseCode.getMessage();
    }

    public GlobalBody(ResponseCode responseCode, String message) {
        this.status = responseCode.getStatus();
        this.message = responseCode.getMessage();
        this.trace = message;
    }

    public static GlobalBody<Void> success() {
        return new GlobalBody<>(ResponseCode.OK);
    }

    public static <T> GlobalBody<T> successWithData(T data) {
        return new GlobalBody<>(data, ResponseCode.OK);
    }

    public static GlobalBody<Void> error() {
        return new GlobalBody<>(ResponseCode.UNKNOWN);
    }

    public static GlobalBody<Void> errorWithMessage(String message) {
        return new GlobalBody<>(ResponseCode.UNKNOWN, message);
    }

    public static GlobalBody<Void> errorWithMessage(GlobalException exception) {
        return new GlobalBody<>(exception.getErrorCode(), exception.getMessage());
    }

    public static <T> GlobalBody<T> errorWithMessageData(T data, GlobalException exception) {
        return new GlobalBody<>(data, exception.getErrorCode(), exception.getMessage());
    }

    private static String getRequestUri() {
        if (Objects.isNull(RequestContextHolder.getRequestAttributes())) return null;
        HttpServletRequest req = ((ServletRequestAttributes) Objects
                .requireNonNull(RequestContextHolder.getRequestAttributes())).getRequest();
        return req.getRequestURI();
    }
}
