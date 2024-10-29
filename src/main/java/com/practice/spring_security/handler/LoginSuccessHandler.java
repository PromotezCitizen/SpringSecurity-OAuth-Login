package com.practice.spring_security.handler;

import com.practice.spring_security.domain.RefreshToken;
import com.practice.spring_security.domain.User;
import com.practice.spring_security.exception.ex_user.ex.UserNotFoundException;
import com.practice.spring_security.repository.UserRepository;
import com.practice.spring_security.service.JwtService;
import com.practice.spring_security.service.RefreshTokenService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

@Slf4j
@RequiredArgsConstructor
public class LoginSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) {

        log.info("일반 로그인 성공 핸들러 동작");
        String email = extractUsername(authentication);
        User user = userRepository.findByEmail(email).orElseThrow(UserNotFoundException::new);

        String accessToken = jwtService.createAccessToken(user.getId(), user.getRole().getValue());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user, request);

        response.setStatus(HttpServletResponse.SC_OK);
        jwtService.addAccessTokenToCookie(response, accessToken);
        jwtService.addRefreshTokenToCookie(response, refreshToken.getToken());
    }

    private String extractUsername(Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        return userDetails.getUsername();
    }
}

