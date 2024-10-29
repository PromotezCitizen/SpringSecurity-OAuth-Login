package com.practice.spring_security.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Provider {
    GOOGLE("GOOGLE"),
    NAVER("NAVER"),
    KAKAO("KAKAO"),
    NONE("NONE");

    private final String value;
}
