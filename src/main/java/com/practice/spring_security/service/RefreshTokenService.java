package com.practice.spring_security.service;

import com.practice.spring_security.domain.RefreshToken;
import com.practice.spring_security.domain.User;
import com.practice.spring_security.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Base64;

@Service
@RequiredArgsConstructor
public class RefreshTokenService {

    private static final String USER_AGENT = "User-Agent";

    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtService jwtService;

    public RefreshToken createRefreshToken(User user, HttpServletRequest request) {

        String randomString = generateRefreshToken();

        RefreshToken refreshToken = RefreshToken.builder()
                .token(randomString)
                .expiryDate(LocalDateTime.now().plusDays(7))
                .ipAddress(request.getRemoteAddr())
                .userAgent(request.getHeader(USER_AGENT))
                .user(user)
                .build();

        return refreshTokenRepository.save(refreshToken);
    }

    public void tokenReissue(HttpServletRequest request, HttpServletResponse response) throws IOException {

        String token = jwtService.extractRefreshToken(request)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Refresh token is missing or invalid."));

        RefreshToken refreshToken = refreshTokenRepository.findByToken(token)
                .filter(rt -> refreshTokenValid(rt, request))
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Invalid refresh token."));

        String newAccessToken = jwtService.createAccessToken(refreshToken.getUser().getId(), refreshToken.getUser().getRole().getValue());
        RefreshToken newRefreshToken = createRefreshToken(refreshToken.getUser(), request);

        refreshTokenRepository.delete(refreshToken);

        jwtService.addAccessTokenToCookie(response, newAccessToken);
        jwtService.addRefreshTokenToCookie(response, newRefreshToken.getToken());

    }

    public boolean refreshTokenValid(RefreshToken refreshToken, HttpServletRequest request) {

        return refreshToken.getExpiryDate().isAfter(LocalDateTime.now()) &&
                refreshToken.getIpAddress().equals(request.getRemoteAddr()) &&
                refreshToken.getUserAgent().equals(request.getHeader(USER_AGENT));
    }


    private String generateRefreshToken() {

        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);

        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }
}
