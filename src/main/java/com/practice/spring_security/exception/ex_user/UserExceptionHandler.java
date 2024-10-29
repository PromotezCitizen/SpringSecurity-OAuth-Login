package com.practice.spring_security.exception.ex_user;

import com.practice.spring_security.exception.ErrorResponse;
import com.practice.spring_security.exception.ex_user.ex.*;
import jakarta.mail.MessagingException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class UserExceptionHandler {

    private static final String DUPLICATE_NICKNAME_ERROR = "DUPLICATE_NICKNAME";
    private static final String DUPLICATE_EMAIL_ERROR = "DUPLICATE_EMAIL";
    private static final String USER_NOT_FOUND_ERROR = "USER_NOT_FOUND";
    private static final String UNVERIFIED_EMAIL_ERROR = "UNVERIFIED_EMAIL";
    private static final String CODE_MISMATCH_ERROR = "CODE_MISMATCH";
    private static final String CODE_EXPIRED_ERROR = "CODE_EXPIRED";
    private static final String FAILED_SEND_EMAIL_ERROR = "FAILED_SEND_EMAIL";

    @ExceptionHandler(DuplicateNicknameException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateNickname(DuplicateNicknameException e) {
        ErrorResponse errorResponse = new ErrorResponse(DUPLICATE_NICKNAME_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handleDuplicateEmail(DuplicateEmailException e) {
        ErrorResponse errorResponse = new ErrorResponse(DUPLICATE_EMAIL_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUserNotFound(UserNotFoundException e) {
        ErrorResponse errorResponse = new ErrorResponse(USER_NOT_FOUND_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
    }

    @ExceptionHandler(UnverifiedEmailException.class)
    public ResponseEntity<ErrorResponse> handleUnverifiedEmail(UnverifiedEmailException e) {
        ErrorResponse errorResponse = new ErrorResponse(UNVERIFIED_EMAIL_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN).body(errorResponse);
    }

    @ExceptionHandler(CodeMismatchException.class)
    public ResponseEntity<ErrorResponse> handleCodeMistmatch(CodeMismatchException e) {
        ErrorResponse errorResponse = new ErrorResponse(CODE_MISMATCH_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
    }

    @ExceptionHandler(CodeExpiredException.class)
    public ResponseEntity<ErrorResponse> handleCodeExpired(CodeExpiredException e) {
        ErrorResponse errorResponse = new ErrorResponse(CODE_EXPIRED_ERROR, e.getMessage());
        return ResponseEntity.status(HttpStatus.GONE).body(errorResponse);
    }

    @ExceptionHandler(MessagingException.class)
    public ResponseEntity<ErrorResponse> handleMessagingException(MessagingException e) {
        ErrorResponse errorResponse = new ErrorResponse(FAILED_SEND_EMAIL_ERROR, "이메일 전송 실패");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
    }
}


