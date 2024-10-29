package com.practice.spring_security.exception.ex_user.ex;

public class CodeMismatchException extends RuntimeException {

    public CodeMismatchException() {
        super("인증코드가 올바르지 않습니다.");
    }
}
