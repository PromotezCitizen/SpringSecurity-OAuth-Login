package com.practice.spring_security.handler;

import com.practice.spring_security.domain.CustomOAuth2User;
import com.practice.spring_security.domain.RefreshToken;
import com.practice.spring_security.domain.User;
import com.practice.spring_security.exception.ex_user.ex.UserNotFoundException;
import com.practice.spring_security.properties.OAuth2Properties;
import com.practice.spring_security.repository.UserRepository;
import com.practice.spring_security.service.JwtService;
import com.practice.spring_security.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final OAuth2Properties oAuth2Properties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {
        try {
            CustomOAuth2User oAuth2User = (CustomOAuth2User) authentication.getPrincipal();
            loginSuccess(request, response, oAuth2User);
        } catch (Exception e) {
            e.printStackTrace();
            throw e;
        }

    }

    private void loginSuccess(HttpServletRequest request,
                              HttpServletResponse response,
                              CustomOAuth2User oAuth2User) throws IOException {
        User user = userRepository.findById(oAuth2User.getUserId())
                .orElseThrow(UserNotFoundException::new);

        log.info("user role: {}", oAuth2User.getAuthorities());
        String accessToken = jwtService.createAccessToken(oAuth2User.getUserId(), oAuth2User.getRole().getValue());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, request);

        response.setStatus(HttpServletResponse.SC_OK);
        jwtService.addAccessTokenToCookie(response, accessToken);
        jwtService.addRefreshTokenToCookie(response, refreshToken.getToken());

        try {
            response.sendRedirect(oAuth2Properties.getRedirectUrl());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
