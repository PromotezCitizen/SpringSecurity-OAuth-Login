package com.practice.spring_security.dto.user;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Getter;

@Getter
public class SignupRequestDto {

    @NotBlank(message = "닉네임을 입력해주세요.")
    private String nickname;

    @NotBlank(message = "이메일을 입력해주세요.")
    @Email
    private String email;

    // @Pattern()
    @NotBlank(message = "비밀번호를 입력해주세요.")
    private String password;
}
