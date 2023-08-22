package com.lkc1009.server.security;

import com.baomidou.mybatisplus.core.toolkit.IdWorker;
import com.lkc1009.server.DaoAuthenticationProvider;
import com.lkc1009.server.user.User;
import com.lkc1009.server.user.UserService;
import com.lkc1009.server.util.JwtUtils;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * 自定义登录逻辑
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginService {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final RedisTemplate<Object, Object> redisTemplate;

    public String login(String username, String password) {
        UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new UsernamePasswordAuthenticationToken(username, password);
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider(userService, passwordEncoder);

        Authentication authentication = daoAuthenticationProvider.authenticate(usernamePasswordAuthenticationToken);

        if (Objects.isNull(authentication)) {
            return "用户名或密码错误";
        }

        User user = (User) authentication.getPrincipal();

        long expiration = System.currentTimeMillis() + 1000 * 60 * 60 * 2;
        String token = JwtUtils.createJwt(String.valueOf(IdWorker.getId())
                ,user.getUsername()
                ,new Date(expiration)
                , SignatureAlgorithm.HS512
                ,JwtUtils.base64EncodedSecretKey
        );

        redisTemplate.opsForValue()
                .set("login:user:" + user.getId(), token, expiration, TimeUnit.MILLISECONDS);

        log.info("登录成功，用户名：{}，token：{}", user.getUsername(), token);
        return token;
    }

    public String logout() {
        User user = (User) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        redisTemplate.delete("login:user:" + user.getId());
        return "退出成功";
    }
}
