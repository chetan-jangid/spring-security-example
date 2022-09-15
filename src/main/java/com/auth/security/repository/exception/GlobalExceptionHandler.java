package com.auth.security.repository.exception;

import com.auth.security.repository.exception.dto.AuthenticationExceptionResponse;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<AuthenticationExceptionResponse> handle(UsernameNotFoundException e) {
        return ResponseEntity.badRequest().body(new AuthenticationExceptionResponse(LocalDateTime.now(),
                e.getMessage(), HttpStatus.BAD_REQUEST.value()));
    }

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<AuthenticationExceptionResponse> handle(AuthException e) {
        return ResponseEntity.badRequest().body(new AuthenticationExceptionResponse(LocalDateTime.now(),
                e.getMessage(),HttpStatus.INTERNAL_SERVER_ERROR.value()));
    }
}
