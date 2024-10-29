package com.practice.spring_security.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class VerifyEmailRequestDto {

    @Email
    @NotBlank
    private String email;

    @NotBlank
    private String code;
}
