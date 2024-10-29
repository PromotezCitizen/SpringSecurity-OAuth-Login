package com.practice.spring_security.service;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.practice.spring_security.properties.CommonTimeProperties;
import com.practice.spring_security.properties.JwtProperties;
import com.practice.spring_security.repository.UserRepository;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Arrays;
import java.util.Date;
import java.util.Optional;

@Slf4j
@Service
@Getter
@RequiredArgsConstructor
@Transactional
public class JwtService {
    private final JwtProperties jwtProperties;
    private final UserRepository userRepository;

    public String createAccessToken(Long userId, String role) {
        Date now = new Date();
        return JWT.create()
                .withSubject(userId.toString())
                .withExpiresAt(new Date(now.getTime() + jwtProperties.getAccess().getExpirationMs()))
                .withClaim(jwtProperties.getClaims().getRole(), role)
                .sign(Algorithm.HMAC512(jwtProperties.getSecret()));
    }

    public Optional<String> extractAccessToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        return cookies == null ?
                Optional.empty() :
                Arrays.stream(cookies)
                        .filter(cookie -> cookie.getName().equals(jwtProperties.getAccess().getCookieName()))
                        .map(Cookie::getValue)
                        .findFirst();
    }

    public Optional<String> extractRefreshToken(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        return cookies == null ?
                Optional.empty() :
                Arrays.stream(cookies)
                        .filter(cookie -> cookie.getName().equals(jwtProperties.getRefresh().getCookieName()))
                        .map(Cookie::getValue)
                        .findFirst();
//        if (cookies != null) {
//            for (Cookie cookie : cookies) {
//                if (cookie.getName().equals(REFRESH_TOKEN_COOKIE)) {
//                    return Optional.of(cookie.getValue());
//                }
//            }
//        }
//        return Optional.empty();
    }

    public Optional<Long> extractUserId(String accessToken) {
        try {
            String userId = JWT.require(Algorithm.HMAC512(jwtProperties.getSecret()))
                    .build()
                    .verify(accessToken)
                    .getSubject();
            return Optional.of(Long.valueOf(userId));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public Optional<String> extractRole(String accessToken) {
        try {
            String role = JWT.require(Algorithm.HMAC512(jwtProperties.getSecret()))
                    .build()
                    .verify(accessToken)
                    .getClaim(jwtProperties.getClaims().getRole())
                    .asString();
            return Optional.ofNullable(role);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    public boolean isTokenValid(String token) {
        try {
            JWT.require(Algorithm.HMAC512(jwtProperties.getSecret())).build().verify(token);
            return true;
        } catch (JWTVerificationException e) {
             log.error("토큰 검증 실패: {}", e.getMessage());
        } catch (Exception e) {
             log.error("예상치 못한 오류: {}", e.getMessage());
        }
        return false;
    }

    public void addAccessTokenToCookie(HttpServletResponse response, String accessToken) {
        Cookie accessTokenCookie = createCookie(
                jwtProperties.getAccess().getCookieName(),
                accessToken,
                CommonTimeProperties.HOUR,
                true,
                true
        );
        response.addCookie(accessTokenCookie);
    }

    public void addRefreshTokenToCookie(HttpServletResponse response, String refreshToken) {
        Cookie refreshTokenCookie = createCookie(
                jwtProperties.getRefresh().getCookieName(),
                refreshToken,
                7 * CommonTimeProperties.DAY,
                true,
                true
        );
        response.addCookie(refreshTokenCookie);
    }

    public void removeAccessAndRefreshTokenFromCookie(HttpServletResponse response) {
        removeAccessTokenFromCookie(response);
        removeRefreshTokenFromCookie(response);
    }

    public void removeAccessTokenFromCookie(HttpServletResponse response) {
        Cookie accessTokenCookie = removeCookie(
                jwtProperties.getAccess().getCookieName(),
                true,
                true
        );
        response.addCookie(accessTokenCookie);
    }

    public void removeRefreshTokenFromCookie(HttpServletResponse response) {
        Cookie refreshTokenCookie = removeCookie(
                jwtProperties.getRefresh().getCookieName(),
                true,
                true
        );
        response.addCookie(refreshTokenCookie);
    }

    private Cookie createCookie(String type, String token, int  age, boolean onlyHttp, boolean onlyHttps) {
        // bearer를 붙이고 싶다면...
//         token = jwtProperties.getBearer() + token;
        Cookie cookie = new Cookie(type, token);
        // XSS 공격 막기
        cookie.setHttpOnly(onlyHttp);
        // HTTPS에서만 전송
        cookie.setSecure(onlyHttps);
        // 어느 경로에서만 허용할 것인가?
        // "/" 라면 모든 경로에서 쿠키 허용
        // "/api" 라면 /api 접두어가 붙은 경로에서만 쿠키 허용
        cookie.setPath("/");
        // 쿠키의 유효기간 설정
        cookie.setMaxAge(age);
        return cookie;
    }

    // 유효기간이 0인 쿠키를 만들어 브라우저에서 바로 삭제하도록 설정
    private Cookie removeCookie(String type, boolean onlyHttp, boolean onlyHttps) {
        Cookie cookie = new Cookie(type, null);
        // XSS 공격 막기
        cookie.setHttpOnly(onlyHttp);
        // HTTPS에서만 전송
        cookie.setSecure(onlyHttps);
        // 어느 경로에서만 허용할 것인가?
        // "/" 라면 모든 경로에서 쿠키 허용
        // "/api" 라면 /api 접두어가 붙은 경로에서만 쿠키 허용
        cookie.setPath("/");
        // 쿠키의 유효기간 설정
        cookie.setMaxAge(0);
        return cookie;
    }
}
