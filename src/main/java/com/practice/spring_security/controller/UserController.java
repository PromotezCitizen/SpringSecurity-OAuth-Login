package com.practice.spring_security.controller;

import com.practice.spring_security.domain.CustomUserDetails;
import com.practice.spring_security.dto.user.SignupRequestDto;
import com.practice.spring_security.dto.user.UserInfoResponseDto;
import com.practice.spring_security.dto.user.VerifyEmailRequestDto;
import com.practice.spring_security.service.EmailService;
import com.practice.spring_security.service.JwtService;
import com.practice.spring_security.service.UserService;
import jakarta.mail.MessagingException;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;
    private final EmailService emailService;

    @PostMapping("/signup")
    public ResponseEntity<Void> createUser(@RequestBody @Valid SignupRequestDto request) {
            userService.signup(request);
            return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @GetMapping("/user")
    public ResponseEntity<UserInfoResponseDto> readUser(@AuthenticationPrincipal CustomUserDetails customUserDetails) {
            UserInfoResponseDto response = userService.loadUserInfo(customUserDetails.getUserId());
            return ResponseEntity.ok(response);
    }

    @DeleteMapping("/user")
    public ResponseEntity<Void> deleteUser(
            @AuthenticationPrincipal CustomUserDetails customUserDetails,
            HttpServletResponse response
    ) {
        userService.withdrawal(customUserDetails.getUserId());
        jwtService.removeAccessAndRefreshTokenFromCookie(response);

        return ResponseEntity.noContent().build();
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(HttpServletResponse response) {
        jwtService.removeAccessAndRefreshTokenFromCookie(response);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/email/send")
    public ResponseEntity<Void> sendVerificationEmail(@RequestParam("email") String email) throws MessagingException {
        log.info("인증코드 전송");
        emailService.sendVerificationCode(email);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/auth/email/verify")
    public ResponseEntity<Void> verifyCode(@RequestBody VerifyEmailRequestDto request) {
        log.info("인증코드 검증");
        emailService.verifyCode(request.getEmail(), request.getCode());
        return ResponseEntity.ok().build();
    }
}
