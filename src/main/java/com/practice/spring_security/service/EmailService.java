package com.practice.spring_security.service;

import com.practice.spring_security.exception.ex_user.ex.CodeExpiredException;
import com.practice.spring_security.exception.ex_user.ex.CodeMismatchException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

import java.util.Random;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class EmailService {

    private static final int VERIFY_CODE_EXPIRATION_TIME = 5;
    private static final int EMAIL_VERIFIED_EXPIRATION_TIME = 10;

    private final JavaMailSender mailSender;
    private final StringRedisTemplate redisTemplate;
    private final RedisService redisService;

    public void sendVerificationCode(String email) throws MessagingException {

        String verificationCode = generateVerificationCode();
        redisService.set(email, verificationCode, VERIFY_CODE_EXPIRATION_TIME, TimeUnit.MINUTES);

        log.info("전송한 인증 코드: {}", verificationCode);

        sendEmail(email, verificationCode);
    }

    public void sendEmail(String email, String verificationCode) throws MessagingException {
        log.info("이메일 Helper 서비스");
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message);

        helper.setTo(email);
        helper.setSubject("이메일 인증 코드");
        helper.setText("인증 코드: " + verificationCode);

        mailSender.send(message);
    }

    public void verifyCode(String email, String code) {
        String storedCode = redisService.get(email).toString();

        if (storedCode == null) {
            throw new CodeExpiredException();
        }

        if (!storedCode.equals(code)) {
            throw new CodeMismatchException();
        }

        redisService.set(email + ":verified", "true", EMAIL_VERIFIED_EXPIRATION_TIME, TimeUnit.MINUTES);
        log.info(redisService.get(email + ":verified").toString());
        redisTemplate.delete(email);
    }

    public String generateVerificationCode() {
        return String.format("%06d", new Random().nextInt(1_000_000));
    }
}
