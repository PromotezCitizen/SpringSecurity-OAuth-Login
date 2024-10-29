package com.practice.spring_security.exception.ex_user.ex;

public class CodeExpiredException extends RuntimeException {

    public CodeExpiredException() {
        super("코드가 만료되었습니다.\n재발급 후 다시 시도해주세요.");
    }
}
