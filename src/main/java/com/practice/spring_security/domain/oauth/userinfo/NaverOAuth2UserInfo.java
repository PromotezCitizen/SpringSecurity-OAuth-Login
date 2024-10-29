package com.practice.spring_security.domain.oauth.userinfo;

import java.util.Map;

public class NaverOAuth2UserInfo extends OAuth2UserInfo {

    public NaverOAuth2UserInfo(Map<String, Object> attributes) {
        super(attributes);
    }

    @Override
    public String getId() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return response == null ? null : (String) response.get("id");
    }

    @Override
    public String getEmail() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return response == null ? null : (String) response.get("email");
    }

    @Override
    public String getNickname() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return response == null ? null : (String) response.get("name");
    }

    @Override
    public String getImageUrl() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return response == null ? null : (String) response.get("profile_image");
    }
}
