package com.practice.spring_security.domain;

import com.practice.spring_security.enums.Role;
import lombok.Getter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

import java.util.Collection;
import java.util.Map;

@Getter
public class CustomOAuth2User extends DefaultOAuth2User {

    private final Long userId;
    private final String email;
    private final Role role;

    public CustomOAuth2User(Collection<? extends GrantedAuthority> authorities,
                            Map<String, Object> attributes,
                            String nameAttributeKey,
                            Long userId,
                            String email,
                            Role role) {
        super(authorities, attributes, nameAttributeKey);
        this.userId = userId;
        this.email = email;
        this.role = role;
    }
}
