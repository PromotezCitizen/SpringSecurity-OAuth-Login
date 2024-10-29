package com.practice.spring_security.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.practice.spring_security.filter.CustomJsonUsernamePasswordAuthenticationFilter;
import com.practice.spring_security.filter.JwtAccessDeniedHandler;
import com.practice.spring_security.filter.JwtAuthenticationEntryPoint;
import com.practice.spring_security.filter.JwtAuthenticationFilter;
import com.practice.spring_security.repository.UserRepository;
import com.practice.spring_security.handler.LoginFailureHandler;
import com.practice.spring_security.handler.LoginSuccessHandler;
import com.practice.spring_security.handler.OAuth2LoginFailureHandler;
import com.practice.spring_security.handler.OAuth2LoginSuccessHandler;
import com.practice.spring_security.properties.LoginProperties;
import com.practice.spring_security.service.CustomOAuth2UserService;
import com.practice.spring_security.service.JwtService;
import com.practice.spring_security.service.LoginService;
import com.practice.spring_security.service.RefreshTokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    private final LoginService loginService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;
    private final UserRepository userRepository;
    private final ObjectMapper objectMapper;
    private final LoginProperties loginProperties;
    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final OAuth2LoginFailureHandler oAuth2LoginFailureHandler;
    private final CustomOAuth2UserService customOAuth2UserService;
    private final JwtAuthenticationEntryPoint jwtAuthenticationEntryPoint;
    private final JwtAccessDeniedHandler jwtAccessDeniedHandler;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

        http
                // form login 비활성화
                .formLogin(formLogin -> formLogin.disable())
                // 인증 방식. 우리는 jwt와 oauth를 사용하기 때문에 비활성화 해준다.
                .httpBasic(httpBasic -> httpBasic.disable())
                // cors 설정
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                // csrf 끄기. REST API서버를 운용할 경우 필요 없음
                .csrf(csrf -> csrf.disable())
                // X-Frame-Options 헤더 비활성화
                .headers(httpSecurityHeadersConfigurer -> httpSecurityHeadersConfigurer
                        .frameOptions(FrameOptionsConfig::disable)
                )
                // session 상태를 stateless, 즉 세션 상태를 유지하지 않겠다
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                // 특정 경로는 허용하고 특정 경로는 권한이 필요하고...를 설정
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/api/**", "/login/**").permitAll()
                        .requestMatchers(PathRequest.toH2Console()).permitAll()
                        .anyRequest().authenticated()
                )
                // OAuth 로그인 활성화
                .oauth2Login(oauth2 -> oauth2
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureHandler(oAuth2LoginFailureHandler)
                        .userInfoEndpoint(userInfo -> userInfo.userService(customOAuth2UserService))
                )
                /**
                 * 정보) Filter를 거친 후 로그인이 되면 SecurityContext에 사용자 정보가 담기게 된다.
                 */
                // logout이 로그인 정보보다 더 먼저 필터링 되도록 설정
                // 로그아웃 하면 더이상 인증된 상태가 아니다
                .addFilterAfter(customJsonUsernamePasswordAuthenticationFilter(), LogoutFilter.class)
                // jwt 인증이 완료 되면 로그인을 할 필요가 없다
                .addFilterBefore(jwtAuthenticationProcessingFilter(), CustomJsonUsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(exception -> exception
                        .accessDeniedHandler(jwtAccessDeniedHandler)
                        .authenticationEntryPoint(jwtAuthenticationEntryPoint)
                );

        return http.build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        config.addAllowedOrigin("http://localhost:5173");
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(loginService);
        return new ProviderManager(provider);
    }

    @Bean
    public LoginSuccessHandler loginSuccessHandler() {
        return new LoginSuccessHandler(jwtService, refreshTokenService, userRepository);
    }

    @Bean
    public LoginFailureHandler loginFailureHandler() {
        return new LoginFailureHandler();
    }

    @Bean
    public CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordAuthenticationFilter() {

        CustomJsonUsernamePasswordAuthenticationFilter customJsonUsernamePasswordLoginFilter
                = new CustomJsonUsernamePasswordAuthenticationFilter(objectMapper, loginProperties);

        customJsonUsernamePasswordLoginFilter.setAuthenticationManager(authenticationManager());
        customJsonUsernamePasswordLoginFilter.setAuthenticationSuccessHandler(loginSuccessHandler());
        customJsonUsernamePasswordLoginFilter.setAuthenticationFailureHandler(loginFailureHandler());

        return customJsonUsernamePasswordLoginFilter;
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationProcessingFilter() {
        return new JwtAuthenticationFilter(jwtService);
    }
}