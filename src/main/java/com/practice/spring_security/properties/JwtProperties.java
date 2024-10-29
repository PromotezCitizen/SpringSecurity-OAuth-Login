package com.practice.spring_security.properties;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Getter
@Setter
@Configuration
@ConfigurationProperties(prefix = "spring.jwt")
public class JwtProperties {
    private String secret;
    private String bearer;

    private Claims claims;
    private TokenInfo access;
    private TokenInfo refresh;

    @Getter
    @Setter
    public static class Claims {
        private String role;
        private String userId;
    }

    @Getter
    @Setter
    public static class TokenInfo {
        private long expirationMs;
        private String header;
        private String subjectName;
        private String cookieName;
    }
}
