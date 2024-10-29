package com.practice.spring_security.service;

import com.practice.spring_security.domain.User;
import com.practice.spring_security.dto.user.SignupRequestDto;
import com.practice.spring_security.dto.user.UserInfoResponseDto;
import com.practice.spring_security.enums.Provider;
import com.practice.spring_security.enums.Role;
import com.practice.spring_security.exception.ex_user.ex.DuplicateEmailException;
import com.practice.spring_security.exception.ex_user.ex.UnverifiedEmailException;
import com.practice.spring_security.exception.ex_user.ex.UserNotFoundException;
import com.practice.spring_security.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Slf4j
@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;

    @Transactional
    public void signup(SignupRequestDto request) {

        checkEmailVerified(request.getEmail());

        userRepository.findByEmail(request.getEmail())
                .ifPresent(user -> { throw new DuplicateEmailException();});
//        if (userRepository.findByEmail(request.getEmail()).isPresent()) {
//            throw new DuplicateEmailException();
//        }

        userRepository.save(User.builder()
                .nickname(request.getNickname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .provider(Provider.NONE)
                .build()
        );
    }

    public UserInfoResponseDto loadUserInfo(Long userId) {

        return userRepository.findById(userId)
                .map(user ->
                        new UserInfoResponseDto(
                            // user.getImageUrl(),
                            user.getId(),
                            user.getNickname(),
                            user.getEmail(),
                            user.getRole()
                        )
                )
                .orElseThrow(UserNotFoundException::new);
    }

    public void withdrawal(Long userId) {
        User user = userRepository.findById(userId)
                        .orElseThrow(UserNotFoundException::new);
        userRepository.delete(user);
    }

    public void checkEmailVerified(String email) {
        String isVerified = redisTemplate.opsForValue().get(email + ":verified");

        if (isVerified != null) {
            redisTemplate.delete(email + ":verified");
        } else {
            throw new UnverifiedEmailException();
        }
    }
}
