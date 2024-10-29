package com.practice.spring_security.filter;

import com.practice.spring_security.domain.CustomUserDetails;
import com.practice.spring_security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.NullAuthoritiesMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;


    private final GrantedAuthoritiesMapper authoritiesMapper = new NullAuthoritiesMapper();

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {
//        String accessToken = jwtService.extractAccessToken(request)
//                .filter(jwtService::isTokenValid)
//                .orElse(null);
//
//        if (accessToken != null) {
//            // "Bearer "가 붙은 경우 주석 해제
//            // accessToken = accessToken.substring(7);
//            checkAccessTokenAndAuthentication(accessToken);
//        }
        jwtService.extractAccessToken(request)
                .filter(jwtService::isTokenValid)
                .ifPresent(this::checkAccessTokenAndAuthentication);

        filterChain.doFilter(request, response);
    }

    public void checkAccessTokenAndAuthentication(String accessToken) {
        // "Bearer "가 붙은 경우 주석 해제
        // accessToken = accessToken.substring(7);
        Long userId = jwtService.extractUserId(accessToken).orElse(null);
        String role = jwtService.extractRole(accessToken).orElse(null);
        saveAuthentication(userId, role);
    }

    public void saveAuthentication(Long userId, String role) {
        CustomUserDetails customUserDetails = new CustomUserDetails(userId, role);
        Authentication authentication =
                new UsernamePasswordAuthenticationToken(
                        customUserDetails,
                        null,
                        authoritiesMapper.mapAuthorities(customUserDetails.getAuthorities())
                );

        SecurityContextHolder.getContext().setAuthentication(authentication);
    }
}
