package com.practice.spring_security.service;

import com.practice.spring_security.domain.CustomOAuth2User;
import com.practice.spring_security.domain.User;
import com.practice.spring_security.domain.oauth.OAuthAttributes;
import com.practice.spring_security.enums.Provider;
import com.practice.spring_security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Map;

@Slf4j
@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final UserRepository userRepository;

    private static final String REGISTRITION_NAVER = "naver";
    private static final String REGISTRITION_KAKAO = "kakao";

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {

        log.info("로드유저 메서드 동작");

        OAuth2User oAuth2User = loadOAuth2User(oAuth2UserRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();

        String registrationId = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        Provider provider = getProvider(registrationId);

        // 각 회사별로 고유 id를 가져오는 필드 이름이 다르다.
        // google의 경우는 sub이고, 카카오는 id 이런 식
        String userNameAttributeName = getUserNameAttributeName(oAuth2UserRequest);

        OAuthAttributes extractAttributes = OAuthAttributes.of(provider, userNameAttributeName, attributes);
        User user = getUser(extractAttributes, provider);

        return createCustomOAuth2User(user, attributes, extractAttributes);
    }

    private OAuth2User loadOAuth2User(OAuth2UserRequest oAuth2UserRequest) {
        OAuth2UserService<OAuth2UserRequest, OAuth2User> delegate =
                new DefaultOAuth2UserService();
        return delegate.loadUser(oAuth2UserRequest);
    }

    private Provider getProvider(String registrationId) {
        return switch(registrationId) {
            case REGISTRITION_NAVER -> Provider.NAVER;
            case REGISTRITION_KAKAO -> Provider.KAKAO;
            default -> Provider.GOOGLE;
        };
    }

    private String getUserNameAttributeName(OAuth2UserRequest oAuth2UserRequest) {
        return oAuth2UserRequest
                .getClientRegistration()
                .getProviderDetails()
                .getUserInfoEndpoint()
                .getUserNameAttributeName();
    }

    private User getUser(OAuthAttributes attributes, Provider provider) {
        return userRepository.findByEmail(attributes.oauth2UserInfo().getEmail())
                .orElse(saveUser(attributes, provider));
//        User user = userRepository.findByEmail(attributes.getOauth2UserInfo().getEmail())
//                .orElse(null);
//
//        if (user == null) {
//            return saveUser(attributes, provider);
//        }
//
//        return user;
    }

    private User saveUser(OAuthAttributes attributes, Provider provider) {
        User user = attributes.toEntity(provider, attributes.oauth2UserInfo());
        return userRepository.save(user);
    }

    private CustomOAuth2User createCustomOAuth2User(User user,
                                                    Map<String, Object> attributes,
                                                    OAuthAttributes extractAttributes) {
        return new CustomOAuth2User(
                Collections.singleton(new SimpleGrantedAuthority(user.getRole().getValue())),
                attributes,
                extractAttributes.nameAttributeKey(),
                user.getId(),
                user.getEmail(),
                user.getRole()
        );
    }
}
