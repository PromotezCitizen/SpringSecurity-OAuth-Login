package com.practice.spring_security.domain.oauth;

import com.practice.spring_security.domain.User;
import com.practice.spring_security.domain.oauth.userinfo.GoogleOAuth2UserInfo;
import com.practice.spring_security.domain.oauth.userinfo.KakaoOAuth2UserInfo;
import com.practice.spring_security.domain.oauth.userinfo.NaverOAuth2UserInfo;
import com.practice.spring_security.domain.oauth.userinfo.OAuth2UserInfo;
import com.practice.spring_security.enums.Provider;
import com.practice.spring_security.enums.Role;

import java.util.Map;

public record OAuthAttributes(String nameAttributeKey, OAuth2UserInfo oauth2UserInfo) {
    public static OAuthAttributes of(Provider provider,
                                     String userNameAttributeName,
                                     Map<String, Object> attributes) {
        if (userNameAttributeName == null || attributes == null) {
            throw new IllegalArgumentException("User name attribute or attributes must not be null");
        }

        return switch (provider) {
            case KAKAO -> ofKakao(userNameAttributeName, attributes);
            case NAVER -> ofNaver(userNameAttributeName, attributes);
            default -> ofGoogle(userNameAttributeName, attributes); // 기본은 google로
        };
//        if (provider == Provider.NAVER) {
//            return ofNaver(userNameAttributeName, attributes);
//        }
//        if (provider == Provider.KAKAO) {
//            return ofKakao(userNameAttributeName, attributes);
//        }
//        return ofGoogle(userNameAttributeName, attributes);
    }

    private static OAuthAttributes ofKakao(String userNameAttributeName, Map<String, Object> attributes) {
        return new OAuthAttributes(userNameAttributeName, new KakaoOAuth2UserInfo(attributes));
    }

    private static OAuthAttributes ofGoogle(String userNameAttributeName, Map<String, Object> attributes) {
        return new OAuthAttributes(userNameAttributeName, new GoogleOAuth2UserInfo(attributes));
    }

    private static OAuthAttributes ofNaver(String userNameAttributeName, Map<String, Object> attributes) {
        return new OAuthAttributes(userNameAttributeName, new NaverOAuth2UserInfo(attributes));
    }

    public User toEntity(Provider provider, OAuth2UserInfo oauth2UserInfo) {
        return User.builder()
                .provider(provider)
                .providerId(oauth2UserInfo.getId())
                .email(oauth2UserInfo.getEmail())
                .nickname(oauth2UserInfo.getNickname())
                .imageUrl(oauth2UserInfo.getImageUrl())
                .role(Role.USER)
                .build();
    }
}
