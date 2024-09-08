package com.common.config.exception;

import com.common.domain.GlobalBody;
import com.common.enums.ResponseCode;
import jakarta.persistence.EntityNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.mapping.PropertyReferenceException;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.servlet.NoHandlerFoundException;


@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler({GlobalException.class})
    public ResponseEntity<GlobalBody<Object>> handlerGlobalException(GlobalException ex) {
        log.error(ex.getMessage());
        return ResponseEntity
                .status(ex.getHttpStatus())
                .body(GlobalBody.errorWithMessageData(ex.getData(), ex));
    }

    @ExceptionHandler(NoHandlerFoundException.class)
    public ResponseEntity<GlobalBody<Void>> handleNoHandlerFoundException(NoHandlerFoundException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.RESULT_NOT_FOUND;
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode, ex.getMessage()));
    }

    @ExceptionHandler({MethodArgumentNotValidException.class})
    public ResponseEntity<GlobalBody<Void>> handlerMethodArgumentNotValidException(MethodArgumentNotValidException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.INVALID_PARAMETERS;
        FieldError fieldError = ex.getBindingResult().getFieldError();
        String message = String.format("%s: %s", fieldError.getField(), fieldError.getDefaultMessage());
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode, message));
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<GlobalBody<Void>> handleHttpMessageNotReadableException(HttpMessageNotReadableException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.INVALID_PARAMETERS;
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode));
    }

    @ExceptionHandler(PropertyReferenceException.class)
    public ResponseEntity<GlobalBody<Void>> handlePropertyReferenceException(PropertyReferenceException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.INVALID_PARAMETERS;
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode));
    }

    @ExceptionHandler(EntityNotFoundException.class)
    public ResponseEntity<GlobalBody<Void>> handleEntityNotFoundException(EntityNotFoundException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.RESULT_NOT_FOUND;
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<GlobalBody<Void>> handleException(Exception ex) {
        log.error(ex.getMessage());
        return ResponseEntity
                .internalServerError()
                .body(GlobalBody.errorWithMessage(ex.getMessage()));
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<GlobalBody<Void>> handleSecurityException(AccessDeniedException ex) {
        log.error(ex.getMessage());
        ResponseCode responseCode = ResponseCode.ACCOUNT_ACCESS_DENIED;
        return ResponseEntity
                .status(responseCode.getHttpStatus())
                .body(new GlobalBody<>(responseCode));
    }
}
