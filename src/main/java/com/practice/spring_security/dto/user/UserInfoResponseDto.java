package com.practice.spring_security.dto.user;

import com.practice.spring_security.enums.Role;
import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class UserInfoResponseDto {

    // private String imageUrl;
    private Long id;

    private String nickname;

    private String email;

    private Role role;
}
