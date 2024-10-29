package com.practice.spring_security.service;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class RedisService {
    private final RedisTemplate<String, Object> redisTemplate;

    /**
     * TTL이 무한인 Redis key-value 쌍을 저장합니다.
     * @param key Redis에서 사용할 key값을 설정합니다.
     * @param value Redis의 key값에 대응되는 value값입니다.
     */
    public void set(String key, Object value) {
        redisTemplate.opsForValue().set(key, value);
    }

    /**
     * 특정 TTL을 가지는 Redis key-value 쌍을 저장합니다.
     * @param key Redis에서 사용할 key값을 설정합니다.
     * @param value Redis의 key값에 대응되는 value값입니다.
     * @param timeout 타임아웃 시간입니다.
     * @param type "SEC", "MIN", "HOUR" 셋 중 하나입니다.<br/>
     *             지정하지 않은 경우 "일" 단위입니다.<br/>
     */
    public void set(String key, Object value, long timeout, String type) {
        TimeUnit unit = switch (type) {
            case "SEC" -> TimeUnit.SECONDS;
            case "MIN" -> TimeUnit.MINUTES;
            case "HOUR" -> TimeUnit.HOURS;
            default -> TimeUnit.DAYS;
        };
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }

    /**
     * 특정 TTL을 가지는 Redis key-value 쌍을 저장합니다.
     * @param key Redis에서 사용할 key값을 설정합니다.
     * @param value Redis의 key값에 대응되는 value값입니다.
     * @param timeout 타임아웃 시간입니다.
     * @param unit TimeUnit 객체 자체를 사용합니다. String type보다 유용합니다.
     */
    public void set(String key, Object value, long timeout, TimeUnit unit) {
        redisTemplate.opsForValue().set(key, value, timeout, unit);
    }

    /**
     * Redis에 저장된 특정 key의 value를 가져옵니다.
     * @param key Redis에 저장된 value를 가져올 기준 key입니다.
     * @return <code>null</code>(TTL 만료) 또는 <code>Object</code>(TTL 만료되지 않음)
     */
    public Object get(String key) {
        return redisTemplate.opsForValue().get(key);
    }

    /**
     * Redis에 저장된 key-value쌍을 제거합니다.
     * @param key Redis에 저장된 key값
     */
    public void remove(String key) {
        redisTemplate.delete(key);
    }
}
